use crate::agentic::desktop::service::step::signals::analyze_metric_schema;
use anyhow::{anyhow, Result};
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebQuoteSpan, WebSource};
use scraper::{Html, Selector};
use std::collections::HashSet;

use super::constants::{
    READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD, READ_BLOCK_STRUCTURED_SCRIPT_MAX,
    READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS, READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE,
    READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT, READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP,
    READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS, READ_BLOCK_SUPPLEMENTAL_MAX,
};
use super::transport::{
    detect_human_challenge, fetch_html_http_fallback, navigate_browser_retrieval,
};
use super::util::{
    compact_ws, domain_for_url, now_ms, sha256_hex, source_id_for_url, text_content,
};

pub(crate) fn extract_read_blocks(html: &str) -> (Option<String>, Vec<String>) {
    let document = Html::parse_document(html);

    let title_sel = Selector::parse("title").ok();
    let title = title_sel
        .as_ref()
        .and_then(|sel| document.select(sel).next())
        .map(text_content)
        .map(|t| compact_ws(&t))
        .and_then(|t| (!t.trim().is_empty()).then(|| t.trim().to_string()));

    let root = Selector::parse("article")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .or_else(|| {
            Selector::parse("main")
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

    let Ok(block_sel) = Selector::parse("p, li") else {
        return (title, vec![]);
    };

    let mut blocks: Vec<String> = Vec::new();
    for elem in root.select(&block_sel) {
        let raw = compact_ws(&text_content(elem));
        let text = raw.trim();
        if text.is_empty() {
            continue;
        }
        blocks.push(text.to_string());
    }

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

    let low_signal_after_supplemental = {
        let char_count = blocks
            .iter()
            .map(|block| block.chars().count())
            .sum::<usize>();
        let has_metric_payload = blocks.iter().any(|block| {
            let schema = analyze_metric_schema(block);
            schema.has_metric_payload() && schema.numeric_token_hits > 0
        });
        blocks.is_empty()
            || char_count < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD
            || !has_metric_payload
    };
    if low_signal_after_supplemental {
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

fn structured_metric_window_score(segment: &str) -> usize {
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

pub async fn edge_web_read(
    browser: &BrowserDriver,
    url: &str,
    max_chars: Option<u32>,
) -> Result<WebEvidenceBundle> {
    let read_url = url.trim();
    if read_url.is_empty() {
        return Err(anyhow!("Empty URL"));
    }
    let mut retrieval_notes: Vec<String> = Vec::new();
    let mut backend = "edge:read:http".to_string();
    let initial_html = match fetch_html_http_fallback(read_url).await {
        Ok(html) => html,
        Err(http_err) => {
            retrieval_notes.push(format!("http_error={}", http_err));
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
    };

    let mut challenge_reason = detect_human_challenge(read_url, &initial_html);
    let (mut title, mut blocks) = extract_read_blocks(&initial_html);

    let low_signal_blocks = blocks.is_empty()
        || blocks
            .iter()
            .map(|block| block.chars().count())
            .sum::<usize>()
            < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD;
    if challenge_reason.is_some() || low_signal_blocks {
        match navigate_browser_retrieval(browser, read_url).await {
            Ok(browser_html) => {
                let browser_challenge = detect_human_challenge(read_url, &browser_html);
                let (browser_title, browser_blocks) = extract_read_blocks(&browser_html);
                if browser_challenge.is_none() && !browser_blocks.is_empty() {
                    challenge_reason = None;
                    title = browser_title;
                    blocks = browser_blocks;
                    backend = "edge:read:browser".to_string();
                } else if challenge_reason.is_none() {
                    challenge_reason = browser_challenge;
                }
            }
            Err(err) => retrieval_notes.push(format!("browser_probe_error={}", err)),
        }
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
    let source = WebSource {
        source_id: source_id.clone(),
        rank: None,
        url: read_url.to_string(),
        title: title.clone(),
        snippet: None,
        domain: domain_for_url(read_url),
    };
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
        sources: vec![source],
        documents: vec![doc],
    })
}
