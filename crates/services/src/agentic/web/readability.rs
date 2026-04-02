use crate::agentic::desktop::service::step::signals::analyze_metric_schema;
use anyhow::{anyhow, Result};
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebQuoteSpan, WebSource};
use scraper::{ElementRef, Html, Selector};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::constants::{
    READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD, READ_BLOCK_STRUCTURED_SCRIPT_MAX,
    READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS, READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE,
    READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT, READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP,
    READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS, READ_BLOCK_SUPPLEMENTAL_MAX,
};
use super::google_news::{is_google_news_article_wrapper_url, resolve_google_news_article_url};
use super::parsers::{
    parse_json_ld_item_list_sources_from_html,
    parse_same_host_authority_document_sources_from_html,
    parse_same_host_child_collection_sources_from_html,
};
use super::transport::{
    detect_human_challenge, fetch_binary_http_fallback_browser_ua_with_final_url,
    fetch_html_http_fallback_browser_ua, fetch_structured_detail_http_fallback_browser_ua,
    navigate_browser_retrieval, transport_error_is_timeout_or_hang,
};
use super::util::{
    compact_ws, domain_for_url, normalize_url_for_id, now_ms, sha256_hex, source_id_for_url,
    text_content,
};

fn looks_like_structured_metadata_noise(text: &str) -> bool {
    let compact = compact_ws(text);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let marker_hits = [
        "\"@context\"",
        "\"@type\"",
        "datepublished",
        "datemodified",
        "inlanguage",
        "thumbnailurl",
        "contenturl",
        "imageobject",
        "\"width\"",
        "\"height\"",
        "\"caption\"",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    if marker_hits == 0 {
        return false;
    }
    let structured_punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '[' | ']' | '"' | ':'))
        .count();
    marker_hits >= 2
        && (structured_punctuation_hits >= 12
            || lower.contains("\",\"")
            || lower.contains("\":")
            || lower.contains("},{"))
}

fn looks_like_executable_script_noise(text: &str) -> bool {
    let compact = compact_ws(text);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let strong_marker_hits = [
        "crypto.getrandomvalues",
        "document.queryselector",
        "document.getelementbyid",
        "googletag.",
        "adsbygoogle",
        "localstorage",
        "sessionstorage",
        "requestsubmit(",
        "tostring(16)",
        "style.display",
        "queryselector(",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    if strong_marker_hits >= 2 {
        return true;
    }

    let js_marker_hits = [
        "function ",
        "=>",
        "document.",
        "window.",
        "return ([1e7]",
        "const ",
        "let ",
        "var ",
        ".style.",
        "addEventListener",
        "remove()",
        "submit(",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    let punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '[' | ']' | ';' | '=' | '>' | '<' | '/'))
        .count();

    js_marker_hits >= 4 && punctuation_hits >= 12
}

fn looks_like_inline_markup_noise(text: &str) -> bool {
    let compact = compact_ws(text);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let attribute_marker_hits = [
        "<svg",
        "</svg",
        "<path",
        "viewbox=",
        "xmlns=",
        "width=",
        "height=",
        "stroke=",
        "fill=",
        "paddingtop=",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    let markup_punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '<' | '>' | '=' | '"' | '/'))
        .count();

    attribute_marker_hits >= 3 && markup_punctuation_hits >= 12
}

fn element_contains_hidden_markup(elem: ElementRef<'_>) -> bool {
    let lower = elem.html().to_ascii_lowercase();
    ["<script", "<style", "<noscript", "<template"]
        .iter()
        .any(|marker| lower.contains(marker))
}

const READ_BLOCK_CANDIDATE_LIMIT: usize = 192;
const READ_BLOCK_MEDIUM_CHAR_FLOOR: usize = 40;
const READ_BLOCK_STRONG_CHAR_FLOOR: usize = 80;
const READ_BLOCK_REPEATING_LABEL_MIN_ITEMS: usize = 3;
const READ_BLOCK_REPEATING_LABEL_MAX_ITEMS: usize = 12;
const READ_BLOCK_REPEATING_LABEL_GROUP_LIMIT: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadSurfaceKind {
    DetailDocument,
    RepeatingLabelSet,
    StructuredRecord,
}

#[derive(Clone, Debug)]
struct ReadSurfaceCandidate {
    kind: ReadSurfaceKind,
    blocks: Vec<String>,
    score: isize,
    primary_signal: usize,
    secondary_signal: usize,
    total_chars: usize,
}

impl ReadSurfaceCandidate {
    fn outranks(&self, other: &Self) -> bool {
        self.score > other.score
            || (self.score == other.score && self.primary_signal > other.primary_signal)
            || (self.score == other.score
                && self.primary_signal == other.primary_signal
                && self.secondary_signal > other.secondary_signal)
            || (self.score == other.score
                && self.primary_signal == other.primary_signal
                && self.secondary_signal == other.secondary_signal
                && self.total_chars > other.total_chars)
            || (self.score == other.score
                && self.primary_signal == other.primary_signal
                && self.secondary_signal == other.secondary_signal
                && self.total_chars == other.total_chars
                && self.blocks.len() < other.blocks.len())
    }

    fn has_minimum_signal(&self) -> bool {
        match self.kind {
            ReadSurfaceKind::DetailDocument => {
                self.total_chars >= READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD || self.primary_signal > 0
            }
            ReadSurfaceKind::RepeatingLabelSet => {
                self.primary_signal >= READ_BLOCK_REPEATING_LABEL_MIN_ITEMS
                    && self.secondary_signal >= 2
            }
            ReadSurfaceKind::StructuredRecord => {
                self.primary_signal >= 2 && self.secondary_signal > 0
            }
        }
    }
}

fn normalized_repeating_label(text: &str) -> Option<String> {
    let compact = compact_ws(text);
    let trimmed = compact
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | ',' | '-' | '.'))
        .trim();
    if trimmed.is_empty()
        || trimmed.chars().count() < 4
        || trimmed.chars().count() > 80
        || !trimmed.chars().any(|ch| ch.is_ascii_alphabetic())
        || looks_like_structured_metadata_noise(trimmed)
        || looks_like_executable_script_noise(trimmed)
        || looks_like_inline_markup_noise(trimmed)
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn element_has_textual_children(elem: ElementRef<'_>) -> bool {
    elem.children().filter_map(ElementRef::wrap).any(|child| {
        let raw = compact_ws(&text_content(child));
        let text = raw.trim();
        !text.is_empty()
            && !looks_like_structured_metadata_noise(text)
            && !looks_like_executable_script_noise(text)
            && !looks_like_inline_markup_noise(text)
    })
}

fn repeating_label_key(elem: ElementRef<'_>) -> Option<String> {
    let tag = elem.value().name();
    let mut classes = elem
        .value()
        .attr("class")
        .unwrap_or_default()
        .split_whitespace()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    classes.sort();
    classes.dedup();

    let parent = elem.parent().and_then(ElementRef::wrap);
    let parent_tag = parent
        .as_ref()
        .map(|value| value.value().name().to_string())
        .unwrap_or_default();
    let mut parent_classes = parent
        .as_ref()
        .and_then(|value| value.value().attr("class"))
        .unwrap_or_default()
        .split_whitespace()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    parent_classes.sort();
    parent_classes.dedup();

    if classes.is_empty() && parent_classes.is_empty() {
        return None;
    }

    Some(format!(
        "{}|{}|{}|{}",
        tag,
        classes.join("."),
        parent_tag,
        parent_classes.join(".")
    ))
}

fn repeating_label_blocks(root: ElementRef<'_>) -> Vec<String> {
    let Ok(selector) = Selector::parse("div, a, li, span, h3, h4, h5, td, dd") else {
        return Vec::new();
    };

    let mut groups = HashMap::<String, Vec<String>>::new();
    let mut group_seen = HashMap::<String, HashSet<String>>::new();
    for element in root.select(&selector).take(READ_BLOCK_CANDIDATE_LIMIT * 4) {
        if element_contains_hidden_markup(element) || element_has_textual_children(element) {
            continue;
        }
        let raw = compact_ws(&text_content(element));
        let Some(label) = normalized_repeating_label(&raw) else {
            continue;
        };
        let Some(key) = repeating_label_key(element) else {
            continue;
        };
        let normalized = label.to_ascii_lowercase();
        let seen = group_seen.entry(key.clone()).or_default();
        if !seen.insert(normalized) {
            continue;
        }
        groups.entry(key).or_default().push(label);
    }

    let mut ranked_groups = groups
        .into_iter()
        .filter_map(|(key, items)| {
            if items.len() < READ_BLOCK_REPEATING_LABEL_MIN_ITEMS {
                return None;
            }
            let multi_word_hits = items
                .iter()
                .filter(|item| item.split_whitespace().count() >= 2)
                .count();
            let avg_chars =
                items.iter().map(|item| item.chars().count()).sum::<usize>() / items.len().max(1);
            let score = items.len() * 100 + multi_word_hits * 10 + avg_chars.min(40);
            Some((score, key, items))
        })
        .collect::<Vec<_>>();
    ranked_groups.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.2.len().cmp(&right.2.len()))
            .then_with(|| left.1.cmp(&right.1))
    });

    let mut selected = Vec::<String>::new();
    let mut selected_seen = HashSet::new();
    for (_, _, items) in ranked_groups
        .into_iter()
        .take(READ_BLOCK_REPEATING_LABEL_GROUP_LIMIT)
    {
        for item in items {
            let normalized = item.to_ascii_lowercase();
            if selected_seen.insert(normalized) {
                selected.push(item);
            }
            if selected.len() >= READ_BLOCK_REPEATING_LABEL_MAX_ITEMS {
                break;
            }
        }
        if selected.len() >= READ_BLOCK_REPEATING_LABEL_MAX_ITEMS {
            break;
        }
    }
    if selected.len() < READ_BLOCK_REPEATING_LABEL_MIN_ITEMS {
        return Vec::new();
    }
    selected
}

fn structured_record_blocks(root: ElementRef<'_>) -> Vec<String> {
    let Ok(row_selector) = Selector::parse("tr") else {
        return Vec::new();
    };
    let Ok(cell_selector) = Selector::parse("th, td") else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut blocks = Vec::new();
    for row in root
        .select(&row_selector)
        .take(READ_BLOCK_SUPPLEMENTAL_MAX * 4)
    {
        let cells = row
            .select(&cell_selector)
            .map(|cell| {
                compact_ws(&text_content(cell))
                    .replace('\u{00b0}', "°")
                    .trim()
                    .trim_end_matches(':')
                    .to_string()
            })
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if cells.len() < 2 {
            continue;
        }
        let label = cells[0].trim();
        let value = cells[1].trim();
        if !label.chars().any(|ch| ch.is_ascii_alphabetic())
            || !value
                .chars()
                .any(|ch| ch.is_ascii_alphabetic() || ch.is_ascii_digit())
        {
            continue;
        }
        let block = format!("{} {}", label, value);
        if looks_like_structured_metadata_noise(&block)
            || looks_like_executable_script_noise(&block)
            || looks_like_inline_markup_noise(&block)
        {
            continue;
        }
        let normalized = block.to_ascii_lowercase();
        if !seen.insert(normalized) {
            continue;
        }
        blocks.push(block);
        if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
            break;
        }
    }
    blocks
}

fn detail_document_blocks(root: ElementRef<'_>, block_sel: &Selector) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut blocks = Vec::new();
    for elem in root.select(block_sel) {
        if element_contains_hidden_markup(elem) {
            continue;
        }
        let raw = compact_ws(&text_content(elem));
        let text = raw.trim();
        if text.is_empty()
            || looks_like_structured_metadata_noise(text)
            || looks_like_executable_script_noise(text)
            || looks_like_inline_markup_noise(text)
        {
            continue;
        }
        let normalized = text.to_ascii_lowercase();
        if !seen.insert(normalized) {
            continue;
        }
        blocks.push(text.to_string());
    }
    blocks
}

fn candidate_block_is_sentence_like(block: &str) -> bool {
    let word_count = block.split_whitespace().count();
    if word_count < 5 {
        return false;
    }
    let punctuation_hits = block
        .chars()
        .filter(|ch| matches!(ch, '.' | '!' | '?' | ';' | ':'))
        .count();
    punctuation_hits > 0 || block.chars().count() >= READ_BLOCK_STRONG_CHAR_FLOOR
}

fn detail_document_signal_score(blocks: &[String]) -> (isize, usize, usize, usize) {
    let mut total_chars = 0usize;
    let mut strong_blocks = 0usize;
    let mut sentence_like_blocks = 0usize;
    let mut short_blocks = 0usize;
    let mut digit_blocks = 0usize;
    let mut observation_metric_blocks = 0usize;
    let mut horizon_dominated_blocks = 0usize;

    for block in blocks {
        let chars = block.chars().count();
        total_chars = total_chars.saturating_add(chars);
        if chars >= READ_BLOCK_STRONG_CHAR_FLOOR {
            strong_blocks = strong_blocks.saturating_add(1);
        } else if chars < READ_BLOCK_MEDIUM_CHAR_FLOOR {
            short_blocks = short_blocks.saturating_add(1);
        }
        if candidate_block_is_sentence_like(block) {
            sentence_like_blocks = sentence_like_blocks.saturating_add(1);
        }
        if block.chars().any(|ch| ch.is_ascii_digit()) {
            digit_blocks = digit_blocks.saturating_add(1);
        }
        let schema = analyze_metric_schema(block);
        if schema.numeric_token_hits > 0 {
            let observation_metric = schema.has_current_observation_payload()
                || (schema.unit_hits > 0 && schema.horizon_hits == 0)
                || (schema.observation_hits > schema.horizon_hits && !schema.axis_hits.is_empty());
            if observation_metric {
                observation_metric_blocks = observation_metric_blocks.saturating_add(1);
            }
            if schema.horizon_hits
                > schema
                    .observation_hits
                    .saturating_add(schema.timestamp_hits)
            {
                horizon_dominated_blocks = horizon_dominated_blocks.saturating_add(1);
            }
        }
    }

    let score = (total_chars.min(4_000) as isize)
        + (strong_blocks as isize * 240)
        + (sentence_like_blocks as isize * 120)
        + (digit_blocks as isize * 40)
        + (observation_metric_blocks as isize * 180)
        - (short_blocks as isize * 90)
        - (horizon_dominated_blocks as isize * 420)
        - (blocks.len().saturating_sub(sentence_like_blocks.max(1)) as isize * 12)
        - if strong_blocks == 0 { 600 } else { 0 };

    (score, strong_blocks, sentence_like_blocks, total_chars)
}

fn read_root_structured_metric_bonus(root: ElementRef<'_>) -> (isize, usize) {
    let blocks = structured_record_blocks(root);
    if blocks.is_empty() {
        return (0, 0);
    }

    let metric_rows = blocks
        .iter()
        .filter(|block| {
            let schema = analyze_metric_schema(block);
            schema.has_metric_payload() && schema.numeric_token_hits > 0
        })
        .count();
    if metric_rows == 0 {
        return (0, 0);
    }

    let root_text = compact_ws(&text_content(root));
    let root_schema = analyze_metric_schema(&root_text);
    let current_observation_bonus = if root_schema.has_current_observation_payload() {
        1_800
    } else if root_schema.observation_hits > root_schema.horizon_hits {
        900
    } else {
        0
    };

    (
        current_observation_bonus + (metric_rows as isize * 260),
        metric_rows,
    )
}

fn repeating_label_surface_candidate(blocks: Vec<String>) -> Option<ReadSurfaceCandidate> {
    if blocks.len() < READ_BLOCK_REPEATING_LABEL_MIN_ITEMS {
        return None;
    }
    let block_count = blocks.len();
    let multi_word_hits = blocks
        .iter()
        .filter(|block| block.split_whitespace().count() >= 2)
        .count();
    let total_chars = blocks
        .iter()
        .map(|block| block.chars().count())
        .sum::<usize>();
    let avg_chars = total_chars / block_count.max(1);
    if multi_word_hits < 2 && avg_chars < 14 {
        return None;
    }
    let single_word_count = block_count.saturating_sub(multi_word_hits);
    let score = (block_count as isize * 160)
        + (multi_word_hits as isize * 180)
        + ((total_chars.min(1_200) / 3) as isize)
        - (single_word_count as isize * 110);
    Some(ReadSurfaceCandidate {
        kind: ReadSurfaceKind::RepeatingLabelSet,
        blocks,
        score,
        primary_signal: block_count,
        secondary_signal: multi_word_hits,
        total_chars,
    })
}

fn structured_record_surface_candidate(blocks: Vec<String>) -> Option<ReadSurfaceCandidate> {
    if blocks.len() < 2 {
        return None;
    }
    let block_count = blocks.len();

    let metric_rows = blocks
        .iter()
        .filter(|block| {
            let schema = analyze_metric_schema(block);
            schema.has_metric_payload() && schema.numeric_token_hits > 0
        })
        .count();
    if metric_rows == 0 {
        return None;
    }

    let total_chars = blocks
        .iter()
        .map(|block| block.chars().count())
        .sum::<usize>();
    let score = (block_count as isize * 120)
        + (metric_rows as isize * 180)
        + ((total_chars.min(800) / 4) as isize);
    Some(ReadSurfaceCandidate {
        kind: ReadSurfaceKind::StructuredRecord,
        blocks,
        score,
        primary_signal: block_count,
        secondary_signal: metric_rows,
        total_chars,
    })
}

fn detail_document_surface_candidate(blocks: Vec<String>) -> Option<ReadSurfaceCandidate> {
    if blocks.is_empty() {
        return None;
    }
    let (score, strong_blocks, sentence_like_blocks, total_chars) =
        detail_document_signal_score(&blocks);
    Some(ReadSurfaceCandidate {
        kind: ReadSurfaceKind::DetailDocument,
        blocks,
        score,
        primary_signal: strong_blocks,
        secondary_signal: sentence_like_blocks,
        total_chars,
    })
}

fn best_surface_candidate_for_blocks(blocks: &[String]) -> Option<ReadSurfaceCandidate> {
    let mut best = None::<ReadSurfaceCandidate>;
    for candidate in [
        detail_document_surface_candidate(blocks.to_vec()),
        structured_record_surface_candidate(blocks.to_vec()),
        repeating_label_surface_candidate(blocks.to_vec()),
    ]
    .into_iter()
    .flatten()
    {
        match best.as_ref() {
            Some(current) if !candidate.outranks(current) => {}
            _ => best = Some(candidate),
        }
    }
    best
}

fn select_best_alternate_surface_candidate(document: &Html) -> Option<ReadSurfaceCandidate> {
    let Ok(candidate_sel) = Selector::parse("article, main, [role='main'], section, div, body")
    else {
        return None;
    };

    let mut best = None::<ReadSurfaceCandidate>;

    for root in document
        .select(&candidate_sel)
        .take(READ_BLOCK_CANDIDATE_LIMIT)
    {
        for candidate in [
            repeating_label_surface_candidate(repeating_label_blocks(root)),
            structured_record_surface_candidate(structured_record_blocks(root)),
        ]
        .into_iter()
        .flatten()
        {
            match best.as_ref() {
                Some(current) if !candidate.outranks(current) => {}
                _ => best = Some(candidate),
            }
        }
    }

    best
}

fn select_best_read_root<'a>(document: &'a Html, block_sel: &Selector) -> Option<ElementRef<'a>> {
    let candidate_sel = Selector::parse("article, main, [role='main'], section, div, body").ok()?;
    let mut best_root = None::<ElementRef<'a>>;
    let mut best_score = isize::MIN;
    let mut best_strong_blocks = 0usize;
    let mut best_sentence_like_blocks = 0usize;
    let mut best_total_chars = 0usize;
    let mut best_block_count = usize::MAX;

    for root in document
        .select(&candidate_sel)
        .take(READ_BLOCK_CANDIDATE_LIMIT)
    {
        let blocks = detail_document_blocks(root, block_sel);
        if blocks.is_empty() {
            continue;
        }
        let (score, strong_blocks, sentence_like_blocks, total_chars) =
            detail_document_signal_score(&blocks);
        let (structured_bonus, structured_metric_rows) = read_root_structured_metric_bonus(root);
        let adjusted_score = score.saturating_add(structured_bonus);
        let is_better = adjusted_score > best_score
            || (adjusted_score == best_score
                && structured_metric_rows > 0
                && best_strong_blocks == 0)
            || (adjusted_score == best_score && structured_metric_rows > best_sentence_like_blocks)
            || (adjusted_score == best_score && strong_blocks > best_strong_blocks)
            || (adjusted_score == best_score
                && strong_blocks == best_strong_blocks
                && sentence_like_blocks > best_sentence_like_blocks)
            || (adjusted_score == best_score
                && strong_blocks == best_strong_blocks
                && sentence_like_blocks == best_sentence_like_blocks
                && total_chars > best_total_chars)
            || (adjusted_score == best_score
                && strong_blocks == best_strong_blocks
                && sentence_like_blocks == best_sentence_like_blocks
                && total_chars == best_total_chars
                && blocks.len() < best_block_count);
        if !is_better {
            continue;
        }
        best_root = Some(root);
        best_score = adjusted_score;
        best_strong_blocks = strong_blocks;
        best_sentence_like_blocks = sentence_like_blocks;
        best_total_chars = total_chars;
        best_block_count = blocks.len();
    }

    best_root
}

pub(crate) fn extract_read_blocks_for_url(
    _read_url: &str,
    html: &str,
) -> (Option<String>, Vec<String>) {
    let document = Html::parse_document(html);

    let title_sel = Selector::parse("title").ok();
    let title = title_sel
        .as_ref()
        .and_then(|sel| document.select(sel).next())
        .map(text_content)
        .map(|t| compact_ws(&t))
        .and_then(|t| (!t.trim().is_empty()).then(|| t.trim().to_string()));

    let Ok(block_sel) = Selector::parse("p, li") else {
        return (title, vec![]);
    };
    let root = select_best_read_root(&document, &block_sel)
        .or_else(|| {
            Selector::parse("article")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        })
        .or_else(|| {
            Selector::parse("main")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        })
        .or_else(|| {
            Selector::parse("[role='main']")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        })
        .or_else(|| {
            Selector::parse("body")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        });

    let Some(root) = root else {
        return (title, vec![]);
    };

    let mut blocks = detail_document_blocks(root, &block_sel);

    let primary_char_count = blocks
        .iter()
        .map(|block| block.chars().count())
        .sum::<usize>();
    let primary_has_numeric_signal = blocks
        .iter()
        .any(|block| block.chars().any(|ch| ch.is_ascii_digit()));
    if blocks.is_empty()
        || primary_char_count < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD
        || !primary_has_numeric_signal
    {
        let mut seen = blocks
            .iter()
            .map(|block| block.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        if let Ok(supplemental_sel) = Selector::parse("td, th, dd, dt, span") {
            for elem in root.select(&supplemental_sel) {
                if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
                    break;
                }
                if element_contains_hidden_markup(elem) {
                    continue;
                }
                let raw = compact_ws(&text_content(elem));
                let text = raw.trim();
                if text.is_empty() {
                    continue;
                }
                if text.chars().count() > 80 {
                    continue;
                }
                let has_digit = text.chars().any(|ch| ch.is_ascii_digit());
                let has_alpha = text.chars().any(|ch| ch.is_ascii_alphabetic());
                if !has_digit || !has_alpha {
                    continue;
                }
                let normalized = text.to_ascii_lowercase();
                if !seen.insert(normalized) {
                    continue;
                }
                blocks.push(text.to_string());
            }
        }
    }

    {
        let mut seen = blocks
            .iter()
            .map(|block| block.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        for block in structured_record_blocks(root) {
            if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
                break;
            }
            if seen.insert(block.to_ascii_lowercase()) {
                blocks.push(block);
            }
        }
    }

    let mut current_surface = best_surface_candidate_for_blocks(&blocks);
    if let Some(alternate_surface) = select_best_alternate_surface_candidate(&document) {
        let alternate_outranks_current = current_surface
            .as_ref()
            .map(|candidate| alternate_surface.outranks(candidate))
            .unwrap_or(true);
        if alternate_outranks_current {
            blocks = alternate_surface.blocks.clone();
            current_surface = Some(alternate_surface);
        }
    }

    let low_signal_after_surface_selection = current_surface
        .as_ref()
        .map(|candidate| !candidate.has_minimum_signal())
        .unwrap_or(true);

    if low_signal_after_surface_selection {
        let mut seen = blocks
            .iter()
            .map(|block| block.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        for segment in structured_metric_blocks_from_scripts(&document) {
            if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
                break;
            }
            if seen.insert(segment.to_ascii_lowercase()) {
                blocks.push(segment);
            }
        }
    }

    (title, blocks)
}

pub(crate) fn extract_read_blocks(html: &str) -> (Option<String>, Vec<String>) {
    extract_read_blocks_for_url("", html)
}

pub(crate) fn extract_non_html_read_blocks(raw: &str) -> Vec<String> {
    let compact = compact_ws(raw);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if looks_like_executable_script_noise(trimmed) || looks_like_inline_markup_noise(trimmed) {
        return Vec::new();
    }
    if trimmed.starts_with('<') && trimmed.contains('>') {
        return Vec::new();
    }

    let schema = analyze_metric_schema(trimmed);
    if schema.has_metric_payload()
        && (schema.numeric_token_hits > 0
            || schema.unit_hits > 0
            || schema.currency_hits > 0
            || !schema.axis_hits.is_empty())
    {
        return vec![trimmed.to_string()];
    }

    let lines = raw
        .lines()
        .map(compact_ws)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .take(READ_BLOCK_SUPPLEMENTAL_MAX)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Vec::new();
    }
    let line_has_metric_payload = lines.iter().any(|line| {
        let schema = analyze_metric_schema(line);
        schema.has_metric_payload() && schema.numeric_token_hits > 0
    });
    if line_has_metric_payload {
        return lines;
    }

    Vec::new()
}

fn structured_metric_window_score(segment: &str) -> usize {
    if looks_like_structured_metadata_noise(segment)
        || looks_like_executable_script_noise(segment)
        || looks_like_inline_markup_noise(segment)
    {
        return 0;
    }
    let schema = analyze_metric_schema(segment);
    if !schema.has_metric_payload() || schema.numeric_token_hits == 0 {
        return 0;
    }

    let mut score = schema
        .numeric_token_hits
        .saturating_add(schema.unit_hits.saturating_mul(2))
        .saturating_add(schema.axis_hits.len().saturating_mul(4))
        .saturating_add(schema.observation_hits)
        .saturating_add(schema.timestamp_hits);
    if schema.has_current_observation_payload() {
        score = score.saturating_add(8);
    }
    score
}

fn structured_metric_blocks_from_scripts(document: &Html) -> Vec<String> {
    let Ok(script_sel) = Selector::parse("script") else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut scored_segments = Vec::<(usize, String)>::new();

    for script in document.select(&script_sel) {
        let raw = compact_ws(&text_content(script));
        if raw.is_empty() || !raw.chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let compact = raw
            .chars()
            .take(READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS)
            .collect::<String>();
        let tokens = compact
            .split_whitespace()
            .take(READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT)
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }

        if tokens.len() <= READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS {
            let segment = tokens.join(" ");
            let score = structured_metric_window_score(&segment);
            if score >= READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE
                && seen.insert(segment.to_ascii_lowercase())
            {
                scored_segments.push((score, segment));
            }
            continue;
        }

        let mut start = 0usize;
        while start < tokens.len() {
            let end = (start + READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS).min(tokens.len());
            let segment = tokens[start..end].join(" ");
            let score = structured_metric_window_score(&segment);
            if score >= READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE
                && seen.insert(segment.to_ascii_lowercase())
            {
                scored_segments.push((score, segment));
            }
            if end == tokens.len() {
                break;
            }
            start = start.saturating_add(READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP);
        }
    }

    scored_segments.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.len().cmp(&right.1.len()))
    });
    scored_segments
        .into_iter()
        .take(READ_BLOCK_STRUCTURED_SCRIPT_MAX)
        .map(|(_, segment)| segment)
        .collect()
}

pub(crate) fn build_document_text_and_spans(
    blocks: &[String],
    max_chars: Option<usize>,
) -> (String, Vec<WebQuoteSpan>) {
    let mut content = String::new();
    let mut spans = Vec::new();
    let mut used_chars = 0usize;

    for block in blocks {
        let block_chars = block.chars().count();
        let sep_chars = if content.is_empty() { 0 } else { 2 };

        if let Some(max) = max_chars {
            if used_chars + sep_chars + block_chars > max {
                break;
            }
        }

        if !content.is_empty() {
            content.push_str("\n\n");
            used_chars += 2;
        }

        let start = content.len();
        content.push_str(block);
        used_chars += block_chars;
        let end = content.len();

        spans.push(WebQuoteSpan {
            start_byte: start as u32,
            end_byte: end as u32,
            quote: block.clone(),
        });
    }

    (content, spans)
}

fn url_has_pdf_hint(url: &str) -> bool {
    url.trim().to_ascii_lowercase().contains(".pdf")
}

fn response_is_pdf(final_url: &str, content_type: Option<&str>) -> bool {
    url_has_pdf_hint(final_url)
        || content_type
            .map(|value| value.to_ascii_lowercase().contains("application/pdf"))
            .unwrap_or(false)
}

fn push_pdf_text_block(blocks: &mut Vec<String>, seen: &mut HashSet<String>, paragraph: &str) {
    let compact = compact_ws(paragraph);
    let trimmed = compact.trim();
    if trimmed.is_empty()
        || looks_like_executable_script_noise(trimmed)
        || looks_like_inline_markup_noise(trimmed)
    {
        return;
    }

    let alpha_count = trimmed.chars().filter(|ch| ch.is_alphabetic()).count();
    let word_count = trimmed.split_whitespace().count();
    if alpha_count < 16 && word_count < 4 {
        return;
    }

    let dedupe_key = trimmed.to_ascii_lowercase();
    if seen.insert(dedupe_key) {
        blocks.push(trimmed.to_string());
    }
}

pub(crate) fn extract_pdf_read_blocks_from_bytes(buffer: &[u8]) -> Result<Vec<String>> {
    let pages = pdf_extract::extract_text_from_mem_by_pages(buffer)
        .or_else(|_| pdf_extract::extract_text_from_mem(buffer).map(|text| vec![text]))
        .map_err(|error| anyhow!("pdf text extraction failed: {}", error))?;

    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    for page in pages {
        let normalized = page.replace('\u{000c}', "\n");
        let mut paragraph = String::new();
        for line in normalized.lines().map(compact_ws) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                if !paragraph.is_empty() {
                    push_pdf_text_block(&mut blocks, &mut seen, &paragraph);
                    paragraph.clear();
                }
                continue;
            }

            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(trimmed);
        }
        if !paragraph.is_empty() {
            push_pdf_text_block(&mut blocks, &mut seen, &paragraph);
        }
    }

    if blocks.is_empty() {
        let fallback = pdf_extract::extract_text_from_mem(buffer)
            .map_err(|error| anyhow!("pdf text extraction returned no usable blocks: {}", error))?;
        push_pdf_text_block(&mut blocks, &mut seen, &fallback);
    }

    if blocks.is_empty() {
        return Err(anyhow!("pdf text extraction returned no usable blocks"));
    }

    Ok(blocks)
}

pub async fn edge_web_read(
    browser: &BrowserDriver,
    url: &str,
    max_chars: Option<u32>,
    allow_browser_fallback: bool,
) -> Result<WebEvidenceBundle> {
    let requested_url = url.trim();
    if requested_url.is_empty() {
        return Err(anyhow!("Empty URL"));
    }
    let resolved_google_news_url = if is_google_news_article_wrapper_url(requested_url) {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(8))
            .timeout(Duration::from_millis(3_500))
            .user_agent("Mozilla/5.0 (compatible; ioi-web-retriever/1.0; +https://ioi.local/web)")
            .build()
            .ok();
        match client {
            Some(client) => resolve_google_news_article_url(&client, requested_url).await,
            None => None,
        }
    } else {
        None
    };
    let read_url = resolved_google_news_url.as_deref().unwrap_or(requested_url);

    if url_has_pdf_hint(read_url) {
        let (final_url, content_type, body_bytes) =
            fetch_binary_http_fallback_browser_ua_with_final_url(read_url).await?;
        if response_is_pdf(&final_url, content_type.as_deref()) {
            let blocks = extract_pdf_read_blocks_from_bytes(&body_bytes).map_err(|error| {
                anyhow!(
                    "ERROR_CLASS=LowSignalReadInsufficient PDF extraction failed for {}: {}",
                    final_url,
                    error
                )
            })?;
            let max = max_chars.map(|v| v as usize);
            let (content_text, quote_spans) = build_document_text_and_spans(&blocks, max);
            let content_hash = sha256_hex(content_text.as_bytes());
            let source_id = source_id_for_url(&final_url);

            return Ok(WebEvidenceBundle {
                schema_version: 1,
                retrieved_at_ms: now_ms(),
                tool: "web__read".to_string(),
                backend: "edge:read:http:pdf".to_string(),
                query: None,
                url: Some(final_url.clone()),
                sources: vec![WebSource {
                    source_id: source_id.clone(),
                    rank: None,
                    url: final_url.clone(),
                    title: None,
                    snippet: None,
                    domain: domain_for_url(&final_url),
                }],
                source_observations: vec![],
                documents: vec![WebDocument {
                    source_id,
                    url: final_url,
                    title: None,
                    content_text,
                    content_hash,
                    quote_spans,
                }],
                provider_candidates: vec![],
                retrieval_contract: None,
            });
        }
    }

    let mut retrieval_notes: Vec<String> = Vec::new();
    let mut backend = "edge:read:http".to_string();
    let initial_html = match fetch_html_http_fallback_browser_ua(read_url).await {
        Ok(html) => html,
        Err(http_err) => {
            retrieval_notes.push(format!("http_error={}", http_err));
            if transport_error_is_timeout_or_hang(&http_err) {
                match fetch_structured_detail_http_fallback_browser_ua(read_url).await {
                    Ok(html) => {
                        backend = "edge:read:http:structured".to_string();
                        html
                    }
                    Err(structured_err) => {
                        retrieval_notes.push(format!("structured_http_error={}", structured_err));
                        if !allow_browser_fallback {
                            return Err(anyhow!(
                                "ERROR_CLASS=UnexpectedState web retrieval failed for {}. strict_http_only=true fallback={}",
                                read_url,
                                retrieval_notes.join("; ")
                            ));
                        }
                        let browser_html = navigate_browser_retrieval(browser, read_url)
                            .await
                            .map_err(|browser_err| {
                                anyhow!(
                                    "ERROR_CLASS=UnexpectedState web retrieval failed for {}. {} browser_error={}",
                                    read_url,
                                    retrieval_notes.join("; "),
                                    browser_err
                                )
                            })?;
                        backend = "edge:read:browser".to_string();
                        browser_html
                    }
                }
            } else {
                if !allow_browser_fallback {
                    return Err(anyhow!(
                        "ERROR_CLASS=UnexpectedState web retrieval failed for {}. strict_http_only=true fallback={}",
                        read_url,
                        retrieval_notes.join("; ")
                    ));
                }
                let browser_html = navigate_browser_retrieval(browser, read_url)
                    .await
                    .map_err(|browser_err| {
                        anyhow!(
                            "ERROR_CLASS=UnexpectedState web retrieval failed for {}. {} browser_error={}",
                            read_url,
                            retrieval_notes.join("; "),
                            browser_err
                        )
                    })?;
                backend = "edge:read:browser".to_string();
                browser_html
            }
        }
    };

    let mut resolved_html = initial_html;
    let mut challenge_reason = detect_human_challenge(read_url, &resolved_html);
    let (mut title, mut blocks) = extract_read_blocks_for_url(read_url, &resolved_html);
    if blocks.is_empty() {
        let fallback_blocks = extract_non_html_read_blocks(&resolved_html);
        if !fallback_blocks.is_empty() {
            blocks = fallback_blocks;
        }
    }

    let low_signal_blocks = blocks.is_empty()
        || blocks
            .iter()
            .map(|block| block.chars().count())
            .sum::<usize>()
            < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD;
    if allow_browser_fallback && (challenge_reason.is_some() || low_signal_blocks) {
        match navigate_browser_retrieval(browser, read_url).await {
            Ok(browser_html) => {
                let browser_challenge = detect_human_challenge(read_url, &browser_html);
                let (browser_title, browser_blocks) =
                    extract_read_blocks_for_url(read_url, &browser_html);
                if browser_challenge.is_none() && !browser_blocks.is_empty() {
                    challenge_reason = None;
                    title = browser_title;
                    blocks = browser_blocks;
                    resolved_html = browser_html;
                    backend = "edge:read:browser".to_string();
                } else if browser_challenge.is_none() {
                    let fallback_blocks = extract_non_html_read_blocks(&browser_html);
                    if !fallback_blocks.is_empty() {
                        challenge_reason = None;
                        blocks = fallback_blocks;
                        resolved_html = browser_html;
                        backend = "edge:read:browser".to_string();
                    }
                } else if challenge_reason.is_none() {
                    challenge_reason = browser_challenge;
                }
            }
            Err(err) => retrieval_notes.push(format!("browser_probe_error={}", err)),
        }
    } else if low_signal_blocks {
        retrieval_notes.push("browser_fallback_suppressed=true".to_string());
        return Err(anyhow!(
            "ERROR_CLASS=LowSignalReadInsufficient low-signal content without browser fallback for {}. {}",
            read_url,
            retrieval_notes.join("; ")
        ));
    }

    if let Some(reason) = challenge_reason {
        let suffix = if retrieval_notes.is_empty() {
            String::new()
        } else {
            format!(" fallback={}", retrieval_notes.join("; "))
        };
        return Err(anyhow!(
            "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually, then retry: {}{}",
            reason,
            read_url,
            suffix
        ));
    }

    let max = max_chars.map(|v| v as usize);
    let (content_text, quote_spans) = build_document_text_and_spans(&blocks, max);
    let content_hash = sha256_hex(content_text.as_bytes());

    let source_id = source_id_for_url(read_url);
    let mut sources = vec![WebSource {
        source_id: source_id.clone(),
        rank: None,
        url: read_url.to_string(),
        title: title.clone(),
        snippet: None,
        domain: domain_for_url(read_url),
    }];
    let mut seen_source_urls = sources
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    for extracted in parse_json_ld_item_list_sources_from_html(
        read_url,
        &resolved_html,
        READ_BLOCK_SUPPLEMENTAL_MAX,
    ) {
        let key = normalize_url_for_id(&extracted.url);
        if seen_source_urls.insert(key) {
            sources.push(extracted);
        }
    }
    for extracted in parse_same_host_child_collection_sources_from_html(
        read_url,
        &resolved_html,
        READ_BLOCK_SUPPLEMENTAL_MAX,
    ) {
        let key = normalize_url_for_id(&extracted.url);
        if seen_source_urls.insert(key) {
            sources.push(extracted);
        }
    }
    for extracted in parse_same_host_authority_document_sources_from_html(
        read_url,
        &resolved_html,
        READ_BLOCK_SUPPLEMENTAL_MAX,
    ) {
        let key = normalize_url_for_id(&extracted.url);
        if seen_source_urls.insert(key) {
            sources.push(extracted);
        }
    }
    let doc = WebDocument {
        source_id,
        url: read_url.to_string(),
        title,
        content_text,
        content_hash,
        quote_spans,
    };

    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__read".to_string(),
        backend,
        query: None,
        url: Some(read_url.to_string()),
        sources,
        source_observations: vec![],
        documents: vec![doc],
        provider_candidates: vec![],
        retrieval_contract: None,
    })
}
