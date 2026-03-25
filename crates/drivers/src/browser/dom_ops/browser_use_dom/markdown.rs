use super::BrowserUseDomTreeNode;
use html2md_rs::to_md::safe_from_html_to_md;
use regex::Regex;
use std::sync::OnceLock;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserUseMarkdownChunk {
    pub(crate) content: String,
    pub(crate) chunk_index: usize,
    pub(crate) total_chunks: usize,
    pub(crate) char_offset_start: usize,
    pub(crate) char_offset_end: usize,
    pub(crate) overlap_prefix: String,
    pub(crate) has_more: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockType {
    Header,
    CodeFence,
    Table,
    ListItem,
    Paragraph,
    Blank,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct AtomicBlock {
    block_type: BlockType,
    lines: Vec<String>,
    char_start: usize,
    char_end: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MarkdownRenderOptions {
    extract_links: bool,
    extract_images: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InlineContext {
    Normal,
    TableCell,
    Heading,
}

fn url_encoded_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"%[0-9A-Fa-f]{2}").expect("valid url-encoding regex"))
}

fn json_code_block_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"`\{["\w].*?\}`"#).expect("valid json code block regex"))
}

fn json_type_blob_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"\{"\$type":[^}]{100,}\}"#).expect("valid json type regex"))
}

fn nested_json_blob_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"\{"[^"]{5,}":\{[^}]{100,}\}"#).expect("valid nested json regex")
    })
}

fn excessive_newline_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\n{4,}").expect("valid newline regex"))
}

fn char_len(text: &str) -> usize {
    text.chars().count()
}

fn is_table_row(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('|') && trimmed.ends_with('|')
}

fn is_list_item(line: &str) -> bool {
    let trimmed = line.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() {
        return false;
    }

    if matches!(trimmed.chars().next(), Some('-' | '*' | '+')) {
        return trimmed.chars().nth(1) == Some(' ');
    }

    let digits = trimmed.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits == 0 {
        return false;
    }

    matches!(trimmed.chars().nth(digits), Some('.' | ')'))
        && trimmed.chars().nth(digits + 1) == Some(' ')
}

fn is_list_continuation(line: &str) -> bool {
    line.starts_with("  ") || line.starts_with('\t')
}

fn block_text(block: &AtomicBlock) -> String {
    block.lines.join("\n")
}

fn table_header(block: &AtomicBlock) -> Option<String> {
    if block.block_type != BlockType::Table || block.lines.len() < 2 {
        return None;
    }

    let separator = &block.lines[1];
    (separator.contains("---") || separator.contains("- -"))
        .then(|| format!("{}\n{}", block.lines[0], block.lines[1]))
}

fn preprocess_markdown_content(content: &str, max_newlines: usize) -> (String, usize) {
    let original_length = char_len(content);

    let content = json_code_block_regex()
        .replace_all(content, "")
        .into_owned();
    let content = json_type_blob_regex()
        .replace_all(&content, "")
        .into_owned();
    let content = nested_json_blob_regex()
        .replace_all(&content, "")
        .into_owned();
    let content = excessive_newline_regex()
        .replace_all(&content, "\n".repeat(max_newlines))
        .into_owned();

    let filtered = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return false;
            }
            !((trimmed.starts_with('{') || trimmed.starts_with('[')) && char_len(trimmed) > 100)
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    let chars_filtered = original_length.saturating_sub(char_len(&filtered));
    (filtered, chars_filtered)
}

fn markdown_tag_name(node: &BrowserUseDomTreeNode) -> Option<String> {
    (node.node_type == 1).then(|| node.node_name.trim().to_ascii_lowercase())
}

fn markdown_text_value(node: &BrowserUseDomTreeNode) -> Option<&str> {
    node.node_value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn markdown_is_hidden_json_code(node: &BrowserUseDomTreeNode, tag: &str) -> bool {
    if tag != "code" {
        return false;
    }

    let style = node
        .attributes
        .get("style")
        .map(String::as_str)
        .unwrap_or_default();
    let compact_style = style.replace(' ', "").to_ascii_lowercase();
    if compact_style.contains("display:none") {
        return true;
    }

    let element_id = node
        .attributes
        .get("id")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    element_id.contains("bpr-guid") || element_id.contains("data") || element_id.contains("state")
}

fn markdown_should_skip_element(node: &BrowserUseDomTreeNode, tag: &str) -> bool {
    if matches!(tag, "style" | "script" | "head" | "meta" | "link" | "title") {
        return true;
    }

    if markdown_is_hidden_json_code(node, tag) {
        return true;
    }

    if tag == "img" {
        if let Some(src) = node.attributes.get("src").map(String::as_str) {
            if src.starts_with("data:image/") {
                return true;
            }
        }
    }

    false
}

fn markdown_is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "caption"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tfoot"
            | "thead"
            | "tbody"
            | "tr"
            | "ul"
    )
}

fn markdown_is_block_node(node: &BrowserUseDomTreeNode) -> bool {
    if matches!(node.node_type, 9 | 11) {
        return true;
    }

    let Some(tag) = markdown_tag_name(node) else {
        return false;
    };
    markdown_is_block_tag(&tag) || tag == "img"
}

fn markdown_ordered_children<'a>(
    node: &'a BrowserUseDomTreeNode,
) -> Vec<&'a BrowserUseDomTreeNode> {
    let mut children = Vec::new();
    children.extend(node.shadow_roots.iter());
    if matches!(markdown_tag_name(node).as_deref(), Some("iframe" | "frame")) {
        if let Some(content_document) = node.content_document.as_deref() {
            if content_document.node_type == 9 {
                children.extend(content_document.children.iter());
            } else {
                children.push(content_document);
            }
        }
    } else {
        children.extend(node.children.iter());
    }
    children
}

fn push_inline_fragment(target: &mut String, fragment: &str) {
    if fragment.trim().is_empty() {
        return;
    }

    if target.is_empty() {
        target.push_str(fragment.trim());
        return;
    }

    if fragment.starts_with('\n') || target.ends_with('\n') {
        target.push_str(fragment);
        return;
    }

    let first = fragment.chars().next();
    let needs_space = !target.ends_with(char::is_whitespace)
        && !matches!(
            first,
            Some(',' | '.' | ';' | ':' | '!' | '?' | ')' | ']' | '}')
        );
    if needs_space {
        target.push(' ');
    }
    target.push_str(fragment.trim());
}

fn inline_markdown_escape(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn block_inline_markdown(text: &str) -> String {
    text.lines()
        .map(inline_markdown_escape)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_image_markdown(
    node: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
    context: InlineContext,
) -> String {
    let alt = node
        .attributes
        .get("alt")
        .map(String::as_str)
        .map(inline_markdown_escape)
        .unwrap_or_default();
    let src = node
        .attributes
        .get("src")
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default();

    let should_strip_to_alt = matches!(context, InlineContext::TableCell | InlineContext::Heading)
        && !options.extract_images;
    if should_strip_to_alt {
        return alt;
    }

    if src.is_empty() {
        return alt;
    }

    format!("![{alt}]({src})")
}

fn render_inline_children(
    node: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
    context: InlineContext,
) -> String {
    let mut rendered = String::new();
    for child in markdown_ordered_children(node) {
        let fragment = render_inline_node(child, options, context);
        push_inline_fragment(&mut rendered, &fragment);
    }
    rendered.trim().to_string()
}

fn render_inline_sequence<'a, I>(
    nodes: I,
    options: MarkdownRenderOptions,
    context: InlineContext,
) -> String
where
    I: IntoIterator<Item = &'a BrowserUseDomTreeNode>,
{
    let mut rendered = String::new();
    for node in nodes {
        let fragment = render_inline_node(node, options, context);
        push_inline_fragment(&mut rendered, &fragment);
    }
    rendered.trim().to_string()
}

fn render_inline_node(
    node: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
    context: InlineContext,
) -> String {
    match node.node_type {
        9 | 11 => render_inline_sequence(markdown_ordered_children(node), options, context),
        3 => markdown_text_value(node)
            .map(inline_markdown_escape)
            .unwrap_or_default(),
        8 => String::new(),
        1 => {
            let tag = markdown_tag_name(node)
                .unwrap_or_else(|| node.node_name.trim().to_ascii_lowercase());
            if markdown_should_skip_element(node, &tag) {
                return String::new();
            }

            match tag.as_str() {
                "br" => "\n".to_string(),
                "img" => render_image_markdown(node, options, context),
                "a" => {
                    let text = render_inline_children(node, options, context);
                    if !options.extract_links {
                        return text;
                    }
                    let href = node
                        .attributes
                        .get("href")
                        .map(String::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty());
                    match (text.is_empty(), href) {
                        (false, Some(href)) => format!("[{text}]({href})"),
                        (false, None) => text,
                        (true, Some(href)) => href.to_string(),
                        (true, None) => String::new(),
                    }
                }
                "strong" | "b" => {
                    let text = render_inline_children(node, options, context);
                    (!text.is_empty())
                        .then(|| format!("**{text}**"))
                        .unwrap_or_default()
                }
                "em" | "i" => {
                    let text = render_inline_children(node, options, context);
                    (!text.is_empty())
                        .then(|| format!("*{text}*"))
                        .unwrap_or_default()
                }
                "code" => {
                    let text = render_inline_children(node, options, context);
                    (!text.is_empty())
                        .then(|| format!("`{text}`"))
                        .unwrap_or_default()
                }
                _ => render_inline_children(node, options, context),
            }
        }
        _ => String::new(),
    }
}

fn collect_preformatted_text(node: &BrowserUseDomTreeNode) -> String {
    match node.node_type {
        3 => node.node_value.clone().unwrap_or_default(),
        8 => String::new(),
        9 | 11 => markdown_ordered_children(node)
            .into_iter()
            .map(collect_preformatted_text)
            .collect::<Vec<_>>()
            .join(""),
        1 => {
            let tag = markdown_tag_name(node)
                .unwrap_or_else(|| node.node_name.trim().to_ascii_lowercase());
            if markdown_should_skip_element(node, &tag) {
                return String::new();
            }
            if tag == "br" {
                return "\n".to_string();
            }
            markdown_ordered_children(node)
                .into_iter()
                .map(collect_preformatted_text)
                .collect::<Vec<_>>()
                .join("")
        }
        _ => String::new(),
    }
}

fn render_blockquote(blocks: &[String]) -> Option<String> {
    let quoted = blocks
        .iter()
        .flat_map(|block| {
            block
                .lines()
                .map(|line| format!("> {line}"))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    (!quoted.is_empty()).then(|| quoted.join("\n"))
}

fn escape_table_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', "<br>")
}

fn render_table_markdown(
    node: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
) -> Option<String> {
    fn collect_rows(
        node: &BrowserUseDomTreeNode,
        in_header: bool,
        options: MarkdownRenderOptions,
        out: &mut Vec<(bool, Vec<String>)>,
    ) {
        if node.node_type != 1 {
            for child in markdown_ordered_children(node) {
                collect_rows(child, in_header, options, out);
            }
            return;
        }

        let tag = markdown_tag_name(node).unwrap_or_default();
        match tag.as_str() {
            "thead" => {
                for child in markdown_ordered_children(node) {
                    collect_rows(child, true, options, out);
                }
            }
            "tbody" | "tfoot" | "table" => {
                for child in markdown_ordered_children(node) {
                    collect_rows(child, in_header, options, out);
                }
            }
            "tr" => {
                let mut is_header_row = in_header;
                let mut cells = Vec::new();
                for child in markdown_ordered_children(node) {
                    if child.node_type != 1 {
                        continue;
                    }
                    let Some(cell_tag) = markdown_tag_name(child) else {
                        continue;
                    };
                    if cell_tag == "th" {
                        is_header_row = true;
                    }
                    if matches!(cell_tag.as_str(), "td" | "th") {
                        let rendered =
                            render_inline_children(child, options, InlineContext::TableCell);
                        cells.push(escape_table_cell(&rendered));
                    }
                }
                if !cells.is_empty() {
                    out.push((is_header_row, cells));
                }
            }
            _ => {
                for child in markdown_ordered_children(node) {
                    collect_rows(child, in_header, options, out);
                }
            }
        }
    }

    let mut rows = Vec::new();
    collect_rows(node, false, options, &mut rows);
    if rows.is_empty() {
        return None;
    }

    let header_index = rows
        .iter()
        .position(|(is_header, _)| *is_header)
        .unwrap_or(0);
    let column_count = rows.iter().map(|(_, row)| row.len()).max().unwrap_or(0);
    if column_count == 0 {
        return None;
    }

    let format_row = |cells: &[String]| {
        let mut padded = cells.to_vec();
        while padded.len() < column_count {
            padded.push(String::new());
        }
        format!("| {} |", padded.join(" | "))
    };

    let mut lines = Vec::new();
    let header_cells = rows
        .get(header_index)
        .map(|(_, row)| row.clone())
        .unwrap_or_default();
    lines.push(format_row(&header_cells));
    lines.push(format!(
        "| {} |",
        std::iter::repeat("---")
            .take(column_count)
            .collect::<Vec<_>>()
            .join(" | ")
    ));

    for (index, (_, row)) in rows.into_iter().enumerate() {
        if index == header_index {
            continue;
        }
        lines.push(format_row(&row));
    }

    Some(lines.join("\n"))
}

fn render_list_markdown(
    node: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
    ordered: bool,
    depth: usize,
) -> Option<String> {
    let mut entries = Vec::new();
    let start_index = node
        .attributes
        .get("start")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(1);

    for (offset, child) in markdown_ordered_children(node).into_iter().enumerate() {
        if markdown_tag_name(child).as_deref() != Some("li") {
            continue;
        }

        let mut content_nodes = Vec::new();
        let mut nested_blocks = Vec::new();
        for grandchild in markdown_ordered_children(child) {
            let tag = markdown_tag_name(grandchild);
            if matches!(tag.as_deref(), Some("ul" | "ol")) {
                if let Some(nested) = render_list_markdown(
                    grandchild,
                    options,
                    matches!(tag.as_deref(), Some("ol")),
                    depth + 1,
                ) {
                    nested_blocks.push(nested);
                }
            } else {
                content_nodes.push(grandchild);
            }
        }

        let content = render_inline_sequence(content_nodes, options, InlineContext::Normal);
        let indent = "  ".repeat(depth);
        let marker = if ordered {
            format!("{}.", start_index + offset)
        } else {
            "-".to_string()
        };

        let mut lines = Vec::new();
        if !content.is_empty() {
            lines.push(format!("{indent}{marker} {content}"));
        } else {
            lines.push(format!("{indent}{marker}"));
        }

        for nested in nested_blocks {
            for nested_line in nested.lines() {
                lines.push(format!("{indent}  {nested_line}"));
            }
        }

        entries.push(lines.join("\n"));
    }

    (!entries.is_empty()).then(|| entries.join("\n"))
}

fn flush_inline_buffer(buffer: &mut String, blocks: &mut Vec<String>) {
    let content = buffer.trim();
    if !content.is_empty() {
        blocks.push(content.to_string());
    }
    buffer.clear();
}

fn render_sequence_as_blocks<'a, I>(nodes: I, options: MarkdownRenderOptions) -> Vec<String>
where
    I: IntoIterator<Item = &'a BrowserUseDomTreeNode>,
{
    let mut blocks = Vec::new();
    let mut inline_buffer = String::new();

    for node in nodes {
        if markdown_is_block_node(node) {
            flush_inline_buffer(&mut inline_buffer, &mut blocks);
            blocks.extend(render_node_blocks(node, options));
        } else {
            let fragment = render_inline_node(node, options, InlineContext::Normal);
            push_inline_fragment(&mut inline_buffer, &fragment);
        }
    }

    flush_inline_buffer(&mut inline_buffer, &mut blocks);
    blocks
}

fn render_node_blocks(node: &BrowserUseDomTreeNode, options: MarkdownRenderOptions) -> Vec<String> {
    match node.node_type {
        9 | 11 => render_sequence_as_blocks(markdown_ordered_children(node), options),
        3 => markdown_text_value(node)
            .map(block_inline_markdown)
            .filter(|text| !text.is_empty())
            .into_iter()
            .collect(),
        8 => Vec::new(),
        1 => {
            let tag = markdown_tag_name(node)
                .unwrap_or_else(|| node.node_name.trim().to_ascii_lowercase());
            if markdown_should_skip_element(node, &tag) {
                return Vec::new();
            }

            match tag.as_str() {
                "img" => render_image_markdown(node, options, InlineContext::Normal)
                    .trim()
                    .is_empty()
                    .then(Vec::new)
                    .unwrap_or_else(|| {
                        vec![render_image_markdown(node, options, InlineContext::Normal)]
                    }),
                "table" => render_table_markdown(node, options).into_iter().collect(),
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                    let level = tag[1..].parse::<usize>().unwrap_or(1).clamp(1, 6);
                    let content = render_inline_children(node, options, InlineContext::Heading);
                    (!content.is_empty())
                        .then(|| vec![format!("{} {}", "#".repeat(level), content)])
                        .unwrap_or_default()
                }
                "pre" => {
                    let text = collect_preformatted_text(node)
                        .trim_matches('\n')
                        .to_string();
                    (!text.is_empty())
                        .then(|| vec![format!("```\n{text}\n```")])
                        .unwrap_or_default()
                }
                "blockquote" => {
                    let blocks =
                        render_sequence_as_blocks(markdown_ordered_children(node), options);
                    render_blockquote(&blocks).into_iter().collect()
                }
                "ul" => render_list_markdown(node, options, false, 0)
                    .into_iter()
                    .collect(),
                "ol" => render_list_markdown(node, options, true, 0)
                    .into_iter()
                    .collect(),
                "hr" => vec!["---".to_string()],
                "iframe" | "frame" => node
                    .content_document
                    .as_deref()
                    .map(|content_document| render_node_blocks(content_document, options))
                    .unwrap_or_default(),
                other if markdown_is_block_tag(other) => {
                    let blocks =
                        render_sequence_as_blocks(markdown_ordered_children(node), options);
                    if !blocks.is_empty() {
                        blocks
                    } else {
                        let inline = render_inline_children(node, options, InlineContext::Normal);
                        (!inline.is_empty())
                            .then(|| vec![inline])
                            .unwrap_or_default()
                    }
                }
                _ => {
                    let inline = render_inline_children(node, options, InlineContext::Normal);
                    (!inline.is_empty())
                        .then(|| vec![inline])
                        .unwrap_or_default()
                }
            }
        }
        _ => Vec::new(),
    }
}

fn render_markdown_from_tree_with_options(
    root: &BrowserUseDomTreeNode,
    options: MarkdownRenderOptions,
) -> Option<String> {
    let markdown = render_node_blocks(root, options).join("\n\n");
    let markdown = url_encoded_regex().replace_all(&markdown, "").into_owned();
    let (filtered, _) = preprocess_markdown_content(&markdown, 3);
    (!filtered.trim().is_empty()).then_some(filtered)
}

pub(super) fn extract_clean_markdown_from_html(html: &str) -> Option<String> {
    let markdown = safe_from_html_to_md(html.to_string()).ok()?;
    let markdown = url_encoded_regex().replace_all(&markdown, "").into_owned();
    let (filtered, _) = preprocess_markdown_content(&markdown, 3);
    (!filtered.trim().is_empty()).then_some(filtered)
}

pub(super) fn render_browser_use_markdown_from_tree(
    root: &BrowserUseDomTreeNode,
) -> Option<String> {
    render_markdown_from_tree_with_options(root, MarkdownRenderOptions::default())
}

#[allow(dead_code)]
fn parse_atomic_blocks(content: &str) -> Vec<AtomicBlock> {
    let lines = content.split('\n').map(str::to_string).collect::<Vec<_>>();
    let mut blocks = Vec::new();
    let mut i = 0usize;
    let mut offset = 0usize;

    while i < lines.len() {
        let line = &lines[i];
        let line_len = char_len(line) + 1;

        if line.trim().is_empty() {
            blocks.push(AtomicBlock {
                block_type: BlockType::Blank,
                lines: vec![line.clone()],
                char_start: offset,
                char_end: offset + line_len,
            });
            offset += line_len;
            i += 1;
            continue;
        }

        if line.trim().starts_with("```") {
            let mut fence_lines = vec![line.clone()];
            let mut fence_end = offset + line_len;
            i += 1;
            while i < lines.len() {
                let fence_line = &lines[i];
                let fence_line_len = char_len(fence_line) + 1;
                fence_lines.push(fence_line.clone());
                fence_end += fence_line_len;
                i += 1;
                if fence_line.trim().starts_with("```") && fence_lines.len() > 1 {
                    break;
                }
            }
            blocks.push(AtomicBlock {
                block_type: BlockType::CodeFence,
                lines: fence_lines,
                char_start: offset,
                char_end: fence_end,
            });
            offset = fence_end;
            continue;
        }

        if line.trim_start().starts_with('#') {
            blocks.push(AtomicBlock {
                block_type: BlockType::Header,
                lines: vec![line.clone()],
                char_start: offset,
                char_end: offset + line_len,
            });
            offset += line_len;
            i += 1;
            continue;
        }

        if is_table_row(line) {
            let mut header_lines = vec![line.clone()];
            let mut header_end = offset + line_len;
            i += 1;

            if i < lines.len() && is_table_row(&lines[i]) && lines[i].contains("---") {
                let separator = &lines[i];
                header_lines.push(separator.clone());
                header_end += char_len(separator) + 1;
                i += 1;
            }

            blocks.push(AtomicBlock {
                block_type: BlockType::Table,
                lines: header_lines,
                char_start: offset,
                char_end: header_end,
            });
            offset = header_end;

            while i < lines.len() && is_table_row(&lines[i]) {
                let row = &lines[i];
                let row_len = char_len(row) + 1;
                blocks.push(AtomicBlock {
                    block_type: BlockType::Table,
                    lines: vec![row.clone()],
                    char_start: offset,
                    char_end: offset + row_len,
                });
                offset += row_len;
                i += 1;
            }
            continue;
        }

        if is_list_item(line) {
            let mut list_lines = vec![line.clone()];
            let mut list_end = offset + line_len;
            i += 1;

            while i < lines.len() {
                let next_line = &lines[i];
                let next_len = char_len(next_line) + 1;
                if is_list_item(next_line)
                    || (!next_line.trim().is_empty() && is_list_continuation(next_line))
                {
                    list_lines.push(next_line.clone());
                    list_end += next_len;
                    i += 1;
                    continue;
                }
                break;
            }

            blocks.push(AtomicBlock {
                block_type: BlockType::ListItem,
                lines: list_lines,
                char_start: offset,
                char_end: list_end,
            });
            offset = list_end;
            continue;
        }

        let mut para_lines = vec![line.clone()];
        let mut para_end = offset + line_len;
        i += 1;
        while i < lines.len() && !lines[i].trim().is_empty() {
            let next_line = &lines[i];
            if next_line.trim_start().starts_with('#')
                || next_line.trim().starts_with("```")
                || is_table_row(next_line)
                || is_list_item(next_line)
            {
                break;
            }
            para_lines.push(next_line.clone());
            para_end += char_len(next_line) + 1;
            i += 1;
        }
        blocks.push(AtomicBlock {
            block_type: BlockType::Paragraph,
            lines: para_lines,
            char_start: offset,
            char_end: para_end,
        });
        offset = para_end;
    }

    if !content.ends_with('\n') {
        if let Some(last) = blocks.last_mut() {
            last.char_end = char_len(content);
        }
    }

    blocks
}

#[allow(dead_code)]
pub(crate) fn chunk_markdown_by_structure(
    content: &str,
    max_chunk_chars: usize,
    overlap_lines: usize,
    start_from_char: usize,
) -> Vec<BrowserUseMarkdownChunk> {
    if content.is_empty() {
        return vec![BrowserUseMarkdownChunk {
            content: String::new(),
            chunk_index: 0,
            total_chunks: 1,
            char_offset_start: 0,
            char_offset_end: 0,
            overlap_prefix: String::new(),
            has_more: false,
        }];
    }

    if start_from_char >= char_len(content) {
        return Vec::new();
    }

    let blocks = parse_atomic_blocks(content);
    if blocks.is_empty() {
        return Vec::new();
    }

    let mut raw_chunks: Vec<Vec<AtomicBlock>> = Vec::new();
    let mut current_chunk: Vec<AtomicBlock> = Vec::new();
    let mut current_size = 0usize;

    for block in blocks {
        let block_size = block.char_end.saturating_sub(block.char_start);
        if current_size + block_size > max_chunk_chars && !current_chunk.is_empty() {
            let mut best_split = current_chunk.len();
            for j in (1..current_chunk.len()).rev() {
                if current_chunk[j].block_type == BlockType::Header {
                    let prefix_size = current_chunk[..j]
                        .iter()
                        .map(|entry| entry.char_end.saturating_sub(entry.char_start))
                        .sum::<usize>();
                    if prefix_size >= max_chunk_chars / 2 {
                        best_split = j;
                        break;
                    }
                }
            }
            raw_chunks.push(current_chunk[..best_split].to_vec());
            current_chunk = current_chunk[best_split..].to_vec();
            current_size = current_chunk
                .iter()
                .map(|entry| entry.char_end.saturating_sub(entry.char_start))
                .sum();
        }

        current_chunk.push(block);
        current_size += block_size;
    }

    if !current_chunk.is_empty() {
        raw_chunks.push(current_chunk);
    }

    let total_chunks = raw_chunks.len();
    let mut chunks = Vec::new();
    let mut previous_chunk_last_table_header: Option<String> = None;

    for (idx, chunk_blocks) in raw_chunks.iter().enumerate() {
        let chunk_text = chunk_blocks
            .iter()
            .map(block_text)
            .collect::<Vec<_>>()
            .join("\n");
        let char_start = chunk_blocks
            .first()
            .map(|block| block.char_start)
            .unwrap_or(0);
        let char_end = chunk_blocks
            .last()
            .map(|block| block.char_end)
            .unwrap_or(char_start);

        let mut overlap_prefix = String::new();
        if idx > 0 {
            let previous_text = raw_chunks[idx - 1]
                .iter()
                .map(block_text)
                .collect::<Vec<_>>()
                .join("\n");
            let previous_lines = previous_text.split('\n').collect::<Vec<_>>();

            if chunk_blocks
                .first()
                .is_some_and(|block| block.block_type == BlockType::Table)
                && previous_chunk_last_table_header.is_some()
            {
                let mut combined = previous_chunk_last_table_header
                    .as_deref()
                    .unwrap_or_default()
                    .split('\n')
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if overlap_lines > 0 {
                    for line in previous_lines.iter().rev().take(overlap_lines).rev() {
                        if !combined.iter().any(|entry| entry == line) {
                            combined.push((*line).to_string());
                        }
                    }
                }
                overlap_prefix = combined.join("\n");
            } else if overlap_lines > 0 {
                overlap_prefix = previous_lines
                    .iter()
                    .rev()
                    .take(overlap_lines)
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }

        for block in chunk_blocks {
            if block.block_type == BlockType::Table {
                if let Some(header) = table_header(block) {
                    previous_chunk_last_table_header = Some(header);
                }
            }
        }

        chunks.push(BrowserUseMarkdownChunk {
            content: chunk_text,
            chunk_index: idx,
            total_chunks,
            char_offset_start: char_start,
            char_offset_end: char_end,
            overlap_prefix,
            has_more: idx + 1 < total_chunks,
        });
    }

    if start_from_char > 0 {
        for (idx, chunk) in chunks.iter().enumerate() {
            if chunk.char_offset_end > start_from_char {
                return chunks[idx..].to_vec();
            }
        }
        return Vec::new();
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::{
        chunk_markdown_by_structure, extract_clean_markdown_from_html,
        render_markdown_from_tree_with_options, MarkdownRenderOptions,
    };
    use crate::browser::dom_ops::browser_use_dom::BrowserUseDomTreeNode;
    use std::collections::HashMap;

    fn node(node_type: i64, node_name: &str) -> BrowserUseDomTreeNode {
        BrowserUseDomTreeNode {
            target_id: "target".to_string(),
            frame_id: None,
            backend_node_id: None,
            node_type,
            node_name: node_name.to_string(),
            node_value: None,
            attribute_pairs: Vec::new(),
            attributes: HashMap::new(),
            snapshot: None,
            rect: None,
            visibility_ratio: None,
            is_visible: true,
            has_js_click_listener: false,
            ax_data: Default::default(),
            som_id: None,
            shadow_root_type: None,
            children: Vec::new(),
            shadow_roots: Vec::new(),
            content_document: None,
            hidden_elements_info: Vec::new(),
            has_hidden_content: false,
            should_display: true,
            assigned_interactive: false,
            is_new: false,
            ignored_by_paint_order: false,
            excluded_by_parent: false,
            is_shadow_host: false,
            compound_children: Vec::new(),
        }
    }

    #[test]
    fn markdown_extractor_removes_large_json_blobs() {
        let html = r#"<html><body><p>Hello</p><code style="display:none">{"$type":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}</code></body></html>"#;
        let markdown = extract_clean_markdown_from_html(html).expect("markdown");
        assert!(markdown.contains("Hello"));
        assert!(!markdown.contains("$type"));
    }

    #[test]
    fn chunk_markdown_preserves_table_headers_in_overlap() {
        let markdown = [
            "# Report",
            "",
            "| Name | Value |",
            "| --- | --- |",
            "| Alpha | 1 |",
            "| Beta | 2 |",
            "| Gamma | 3 |",
        ]
        .join("\n");

        let chunks = chunk_markdown_by_structure(&markdown, 55, 2, 0);
        assert!(chunks.len() >= 2);
        assert!(chunks[1].overlap_prefix.contains("| Name | Value |"));
        assert!(chunks[1].overlap_prefix.contains("| --- | --- |"));
    }

    #[test]
    fn tree_markdown_excludes_table_cell_image_urls_by_default() {
        let mut root = node(9, "#document");
        let mut table = node(1, "TABLE");
        let mut row = node(1, "TR");
        let mut cell = node(1, "TD");
        let mut img = node(1, "IMG");
        img.attributes.insert(
            "src".to_string(),
            "http://localhost/images/widget-a.jpg".to_string(),
        );
        img.attributes
            .insert("alt".to_string(), "Widget A".to_string());
        cell.children.push(img);
        row.children.push(cell);
        table.children.push(row);
        root.children.push(table);

        let markdown =
            render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
                .expect("markdown");
        assert!(markdown.contains("Widget A"));
        assert!(!markdown.contains("widget-a.jpg"));
        assert!(!markdown.contains("!["));
    }

    #[test]
    fn tree_markdown_includes_table_cell_image_urls_when_enabled() {
        let mut root = node(9, "#document");
        let mut table = node(1, "TABLE");
        let mut row = node(1, "TR");
        let mut cell = node(1, "TD");
        let mut img = node(1, "IMG");
        img.attributes.insert(
            "src".to_string(),
            "http://localhost/images/widget-a.jpg".to_string(),
        );
        img.attributes
            .insert("alt".to_string(), "Widget A".to_string());
        cell.children.push(img);
        row.children.push(cell);
        table.children.push(row);
        root.children.push(table);

        let markdown = render_markdown_from_tree_with_options(
            &root,
            MarkdownRenderOptions {
                extract_links: false,
                extract_images: true,
            },
        )
        .expect("markdown");
        assert!(markdown.contains("widget-a.jpg"));
        assert!(markdown.contains("![Widget A]"));
    }

    #[test]
    fn tree_markdown_always_keeps_block_images() {
        let mut root = node(9, "#document");
        let mut div = node(1, "DIV");
        let mut img = node(1, "IMG");
        img.attributes.insert(
            "src".to_string(),
            "http://localhost/images/widget-a.jpg".to_string(),
        );
        img.attributes
            .insert("alt".to_string(), "Widget A".to_string());
        div.children.push(img);
        root.children.push(div);

        let markdown =
            render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
                .expect("markdown");
        assert!(markdown.contains("![Widget A](http://localhost/images/widget-a.jpg)"));
    }

    #[test]
    fn tree_markdown_preserves_links_only_when_requested() {
        let mut root = node(9, "#document");
        let mut paragraph = node(1, "P");
        let mut link = node(1, "A");
        link.attributes
            .insert("href".to_string(), "https://example.com/docs".to_string());
        let mut text = node(3, "#text");
        text.node_value = Some("Docs".to_string());
        link.children.push(text);
        paragraph.children.push(link);
        root.children.push(paragraph);

        let without_links =
            render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
                .expect("markdown");
        assert_eq!(without_links, "Docs");

        let with_links = render_markdown_from_tree_with_options(
            &root,
            MarkdownRenderOptions {
                extract_links: true,
                extract_images: false,
            },
        )
        .expect("markdown");
        assert_eq!(with_links, "[Docs](https://example.com/docs)");
    }
}
