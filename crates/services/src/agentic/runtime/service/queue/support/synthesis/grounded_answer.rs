use super::*;
use crate::agentic::runtime::service::RuntimeAgentService;
use tokio::time::Duration;

fn grounded_answer_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 45_000;
    std::env::var("IOI_WEB_MARKDOWN_SYNTHESIS_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

const WEB_PIPELINE_DIRECT_CONTRACT_RETRY_MAX_ATTEMPTS: usize = 2;

fn truncate_for_prompt(input: &str, max_chars: usize) -> String {
    let compact = compact_whitespace(input);
    if compact.len() <= max_chars {
        return compact;
    }
    let mut out = compact.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

fn direct_synthesis_sources_for_pending<'a>(
    pending: &'a PendingSearchCompletion,
) -> Vec<&'a PendingSearchReadSummary> {
    let query_contract = synthesis_query_contract(pending);
    if query_asks_to_find_sources(&query_contract) {
        let mut selected = Vec::new();
        let mut seen_urls = BTreeSet::new();
        for source in pending
            .successful_reads
            .iter()
            .chain(pending.candidate_source_hints.iter())
        {
            let url = source.url.trim();
            if url.is_empty()
                || !seen_urls.insert(crate::agentic::web::normalize_url_for_id(url))
                || is_search_hub_url(url)
                || !is_citable_web_url(url)
            {
                continue;
            }
            let title = source.title.as_deref().unwrap_or_default();
            if is_low_signal_title(title) && is_low_signal_excerpt(&source.excerpt) {
                continue;
            }
            selected.push(source);
            if selected.len() >= 8 {
                break;
            }
        }
        return selected;
    }
    if query_requires_market_quote_grounding(&query_contract) {
        let quote_sources = pending
            .successful_reads
            .iter()
            .filter(|source| market_quote_source_is_quote_grade(source, &query_contract))
            .collect::<Vec<_>>();
        let comparison_required = pending
            .retrieval_contract
            .as_ref()
            .map(|contract| contract.comparison_required)
            .unwrap_or(false)
            || query_requests_comparison(&query_contract);
        let quote_source_count = market_quote_grounding_source_count_for_sources(
            quote_sources.iter().copied(),
            &query_contract,
        );
        let quote_source_floor = market_quote_grounding_floor_for_query(
            &query_contract,
            comparison_required,
            pending.min_sources.max(1) as usize,
        );
        let structured_metrics_ready =
            !market_quote_structured_metrics_required(&query_contract, comparison_required)
                || market_quote_structured_metric_source_count_for_sources(
                    quote_sources.iter().copied(),
                    &query_contract,
                ) >= quote_source_floor;
        if quote_source_count >= quote_source_floor && structured_metrics_ready {
            let mut selected = Vec::new();
            let mut seen_urls = BTreeSet::new();
            for source in quote_sources {
                let url = source.url.trim();
                if !url.is_empty() && seen_urls.insert(url.to_string()) {
                    selected.push(source);
                }
            }
            if comparison_required {
                let mut comparison_context_seen = false;
                for source in pending.successful_reads.iter().filter(|source| {
                    market_quote_source_is_comparison_context_grade(source, &query_contract)
                }) {
                    let url = source.url.trim();
                    if url.is_empty() || !seen_urls.insert(url.to_string()) {
                        continue;
                    }
                    comparison_context_seen = true;
                    selected.push(source);
                }
                if !comparison_context_seen {
                    return Vec::new();
                }
            }
            return selected;
        }
        return Vec::new();
    }

    pending.successful_reads.iter().collect()
}

fn direct_source_context_from_pending(pending: &PendingSearchCompletion) -> Option<String> {
    let query_contract = synthesis_query_contract(pending);
    let source_limit = if query_requires_market_quote_grounding(&query_contract)
        && query_requests_comparison(&query_contract)
    {
        12
    } else {
        8
    };
    let mut seen_urls = BTreeSet::new();
    let mut lines = Vec::new();
    for source in direct_synthesis_sources_for_pending(pending) {
        let url = source.url.trim();
        if url.is_empty() || !seen_urls.insert(url.to_string()) {
            continue;
        }
        let title = source
            .title
            .as_deref()
            .map(compact_source_label)
            .unwrap_or_else(|| compact_source_label(url));
        let excerpt = truncate_for_prompt(&source.excerpt, 900);
        let note = direct_source_use_note(source, &query_contract);
        lines.push(format!(
            "- Title: {title}\n  URL: {url}\n  Evidence: {excerpt}\n  Note: {note}"
        ));
        if lines.len() >= source_limit {
            break;
        }
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn direct_source_use_note(source: &PendingSearchReadSummary, query_contract: &str) -> &'static str {
    if query_requires_market_quote_grounding(query_contract) {
        if market_quote_source_is_quote_grade(source, query_contract) {
            return "Use explicit values from this source for the named asset's live price, market cap, volume, or recent move only when the evidence text states the value.";
        }
        if market_quote_source_is_comparison_context_grade(source, query_contract) {
            return "Use this for thesis, use case, risks, backers, or momentum context only. Do not use it as live quote evidence, do not infer missing units, and never expand bare numbers into market caps or prices.";
        }
    }
    "Use this source for the facts it directly supports; do not infer missing details."
}

fn direct_synthesis_behavior_guidance(query: &str) -> &'static str {
    if query_requires_market_quote_grounding(query) && query_requests_comparison(query) {
        "- For investment comparisons, answer naturally and substantively. Make a cautious call only if the retrieved evidence supports one; otherwise explain what would decide it. Use live price, market cap, volume, and recent-move numbers only when a source note for that same asset explicitly states the value. Use other sources for qualitative thesis, use case, risks, backers, or momentum context. Omit or qualify unsupported dimensions; do not invent missing metrics, infer missing units, or expand bare comparison values such as `5` or `16` into `$5B` or `$16B`.\n"
    } else if query_asks_to_find_sources(query) {
        "- If the user asks to find sources, answer with a short sentence and a `Sources:` list of relevant Markdown links with one concise note on why each source is useful. If the user says current, latest, today, recent, or right now, preserve that temporal qualifier visibly in the first sentence. Do not use `Sources checked` or a retrieval-summary heading.\n"
    } else {
        ""
    }
}

fn direct_synthesis_max_tokens(query: &str) -> u32 {
    if query_requires_market_quote_grounding(query) && query_requests_comparison(query) {
        2200
    } else {
        1200
    }
}

fn markdown_answer_has_source_url_from_sources(
    answer: &str,
    sources: &[&PendingSearchReadSummary],
) -> bool {
    sources.iter().any(|source| {
        let url = source.url.trim();
        !url.is_empty() && answer.contains(url)
    })
}

fn markdown_answer_has_pending_source_url(answer: &str, pending: &PendingSearchCompletion) -> bool {
    markdown_answer_has_source_url_from_sources(
        answer,
        &direct_synthesis_sources_for_pending(pending),
    )
}

fn markdown_link_label(label: &str) -> String {
    compact_source_label(label)
        .replace('[', "(")
        .replace(']', ")")
}

fn direct_answer_source_footer(pending: &PendingSearchCompletion) -> Option<String> {
    let mut lines = vec!["Sources:".to_string()];
    let mut seen_urls = BTreeSet::new();
    for source in direct_synthesis_sources_for_pending(pending) {
        let url = source.url.trim();
        if url.is_empty() || !seen_urls.insert(url.to_string()) {
            continue;
        }
        let label = source
            .title
            .as_deref()
            .map(markdown_link_label)
            .unwrap_or_else(|| markdown_link_label(url));
        lines.push(format!("- [{label}]({url})"));
        if lines.len() >= 7 {
            break;
        }
    }
    (lines.len() > 1).then(|| lines.join("\n"))
}

fn attach_direct_answer_sources_if_needed(
    answer: &str,
    pending: &PendingSearchCompletion,
) -> String {
    if markdown_answer_has_pending_source_url(answer, pending) {
        return answer.trim().to_string();
    }
    let Some(footer) = direct_answer_source_footer(pending) else {
        return answer.trim().to_string();
    };
    format!("{}\n\n{}", answer.trim(), footer)
}

fn markdown_answer_looks_product_safe(answer: &str) -> bool {
    let lower = answer.to_ascii_lowercase();
    ![
        "story 1",
        "story 2",
        "story 3",
        "web retrieval summary",
        "current web findings",
        "sources checked",
        "source role:",
        "use note:",
        "retrieved source notes",
        "quote-grade",
        "deterministic",
        "fixture",
        "daemon_endpoint",
        "workspace_fixture",
        "couldn’t produce a grounded web answer",
        "couldn't produce a grounded web answer",
        "selected model did not return usable",
        "model_synthesis_unavailable",
        "model_answer_unavailable",
        "run date (utc):",
        "run timestamp (utc):",
        "overall confidence:",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn markdown_answer_refuses_supplied_sources(answer: &str) -> bool {
    let lower = answer.to_ascii_lowercase();
    [
        "cannot access the internet",
        "can't access the internet",
        "cannot browse the internet",
        "can't browse the internet",
        "do not have access to current",
        "don't have access to current",
        "i do not have browsing",
        "i don't have browsing",
        "i cannot browse",
        "i can't browse",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn direct_answer_preserves_temporal_source_qualifier(
    answer: &str,
    pending: &PendingSearchCompletion,
) -> bool {
    let query = synthesis_query_contract(pending).to_ascii_lowercase();
    if !query_asks_to_find_sources(&query) {
        return true;
    }
    let answer = answer.to_ascii_lowercase();
    if query.contains("current") && !answer.contains("current") {
        return false;
    }
    if query.contains("latest") && !answer.contains("latest") {
        return false;
    }
    if (query.contains("today") || query.contains("today's"))
        && !(answer.contains("today") || answer.contains("current"))
    {
        return false;
    }
    if query.contains("right now") && !(answer.contains("right now") || answer.contains("current"))
    {
        return false;
    }
    if query.contains("recent") && !(answer.contains("recent") || answer.contains("current")) {
        return false;
    }
    true
}

fn canonical_money_token(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut saw_digit = false;
    for ch in raw.chars() {
        match ch {
            '$' if out.is_empty() => out.push('$'),
            '0'..='9' | '.' => {
                saw_digit = true;
                out.push(ch);
            }
            ch if ch.is_ascii_alphabetic() => out.push(ch.to_ascii_lowercase()),
            _ => {}
        }
    }
    if !out.starts_with('$') || !saw_digit {
        return None;
    }
    Some(
        out.replace("million", "m")
            .replace("billion", "b")
            .replace("trillion", "t")
            .replace("thousand", "k"),
    )
}

fn extract_money_tokens(surface: &str) -> BTreeSet<String> {
    let chars = surface.chars().collect::<Vec<_>>();
    let mut tokens = BTreeSet::new();
    let mut idx = 0;
    while idx < chars.len() {
        if chars[idx] != '$' {
            idx += 1;
            continue;
        }
        let start = idx;
        idx += 1;
        while idx < chars.len()
            && (chars[idx].is_ascii_digit()
                || chars[idx] == '.'
                || chars[idx] == ','
                || chars[idx].is_ascii_whitespace())
        {
            idx += 1;
        }
        let suffix_start = idx;
        while idx < chars.len() && chars[idx].is_ascii_alphabetic() {
            idx += 1;
        }
        let raw = chars[start..idx].iter().collect::<String>();
        if let Some(token) = canonical_money_token(&raw) {
            tokens.insert(token);
        }
        if suffix_start == idx {
            continue;
        }
    }
    tokens
}

fn quote_grade_money_tokens(pending: &PendingSearchCompletion) -> BTreeSet<String> {
    let query = synthesis_query_contract(pending);
    pending
        .successful_reads
        .iter()
        .filter(|source| market_quote_source_is_quote_grade(source, &query))
        .filter(|source| market_quote_source_has_structured_metric_payload(source))
        .flat_map(|source| {
            extract_money_tokens(&format!(
                "{} {}",
                source.title.as_deref().unwrap_or_default(),
                source.excerpt
            ))
        })
        .collect()
}

fn direct_answer_has_unsupported_market_cap_values(
    answer: &str,
    pending: &PendingSearchCompletion,
) -> bool {
    let query = synthesis_query_contract(pending);
    if !query_requires_market_quote_grounding(&query) || !query_requests_comparison(&query) {
        return false;
    }
    let allowed_tokens = quote_grade_money_tokens(pending);
    if allowed_tokens.is_empty() {
        return false;
    }
    for line in answer.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("market cap") {
            continue;
        }
        for token in extract_money_tokens(line) {
            if !allowed_tokens.contains(&token) {
                return true;
            }
        }
    }
    false
}

fn strip_hidden_reasoning_sections(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    loop {
        let Some(start) = rest.to_ascii_lowercase().find("<think>") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let after_start = &rest[start + "<think>".len()..];
        let Some(end) = after_start.to_ascii_lowercase().find("</think>") else {
            break;
        };
        rest = &after_start[end + "</think>".len()..];
    }
    out
}

fn visible_direct_answer_from_raw(raw: &str, pending: &PendingSearchCompletion) -> Option<String> {
    let answer = strip_hidden_reasoning_sections(raw);
    let answer = strip_markdown_code_fence(&answer);
    let answer = strip_product_metadata_lines(&answer);
    let answer = attach_direct_answer_sources_if_needed(&answer, pending);
    if answer.is_empty()
        || !markdown_answer_looks_product_safe(&answer)
        || markdown_answer_refuses_supplied_sources(&answer)
        || !direct_answer_preserves_temporal_source_qualifier(&answer, pending)
        || direct_answer_has_unsupported_market_cap_values(&answer, pending)
        || !markdown_answer_has_pending_source_url(&answer, pending)
    {
        return None;
    }
    Some(answer)
}

fn strip_markdown_code_fence(answer: &str) -> String {
    let trimmed = answer.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else {
        return trimmed.to_string();
    };
    let Some(close_index) = after_open.rfind("```") else {
        return trimmed.trim_matches('`').trim().to_string();
    };
    let fenced = &after_open[..close_index];
    let body = fenced
        .strip_prefix("markdown")
        .or_else(|| fenced.strip_prefix("md"))
        .unwrap_or(fenced)
        .trim_start_matches(|ch: char| ch == '\n' || ch == '\r' || ch.is_whitespace());
    body.trim().to_string()
}

fn strip_product_metadata_lines(answer: &str) -> String {
    const METADATA_MARKERS: [&str; 3] = [
        "Run date (UTC):",
        "Run timestamp (UTC):",
        "Overall confidence:",
    ];

    let mut lines = Vec::new();
    for line in answer.lines() {
        let trimmed = line.trim_start();
        if METADATA_MARKERS
            .iter()
            .any(|marker| trimmed.starts_with(marker))
        {
            continue;
        }

        let earliest_inline_marker = METADATA_MARKERS
            .iter()
            .filter_map(|marker| line.find(marker))
            .min();
        if let Some(index) = earliest_inline_marker {
            let prefix = line[..index].trim_end();
            if !prefix.is_empty() {
                lines.push(prefix.to_string());
            }
            continue;
        }

        lines.push(line.to_string());
    }

    lines.join("\n").trim().to_string()
}

#[cfg(test)]
pub(crate) async fn synthesize_web_pipeline_reply_candidates(
    service: &RuntimeAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> Vec<FinalWebSummaryCandidate> {
    let mut candidates = Vec::new();
    if let Some(mut direct_summary) =
        synthesize_web_pipeline_reply_direct(service, pending, reason).await
    {
        let mut retry_count = 0usize;
        loop {
            let direct_facts =
                final_web_completion_facts_with_rendered_summary(pending, reason, &direct_summary);
            candidates.insert(
                0,
                FinalWebSummaryCandidate {
                    provider: "model_direct_sourced_answer",
                    summary: direct_summary.clone(),
                },
            );
            if final_web_completion_contract_ready(&direct_facts)
                || retry_count >= WEB_PIPELINE_DIRECT_CONTRACT_RETRY_MAX_ATTEMPTS
            {
                break;
            }
            let Some(retry_summary) = synthesize_web_pipeline_reply_direct_contract_retry(
                service,
                pending,
                reason,
                &direct_summary,
                &direct_facts,
            )
            .await
            else {
                break;
            };
            retry_count = retry_count.saturating_add(1);
            direct_summary = retry_summary;
        }
    }
    candidates
}

pub(crate) fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

pub(crate) fn is_iso_utc_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
        && bytes[10] == b'T'
        && bytes[11].is_ascii_digit()
        && bytes[12].is_ascii_digit()
        && bytes[13] == b':'
        && bytes[14].is_ascii_digit()
        && bytes[15].is_ascii_digit()
        && bytes[16] == b':'
        && bytes[17].is_ascii_digit()
        && bytes[18].is_ascii_digit()
        && bytes[19] == b'Z'
}

pub(crate) fn normalize_section_key(label: &str) -> String {
    let mut out = String::new();
    let mut last_was_underscore = false;
    for ch in label.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            out.push(normalized);
            last_was_underscore = false;
            continue;
        }
        if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

pub(crate) fn dedupe_labels(labels: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for label in labels {
        let key = normalize_section_key(&label);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        out.push(label);
    }
    out
}

pub(crate) fn required_section_labels_for_query(query: &str) -> Vec<String> {
    dedupe_labels(
        infer_report_sections(query)
            .into_iter()
            .map(|kind| report_section_label(kind, query))
            .collect(),
    )
}

pub(crate) fn build_required_answer_sections(query: &str) -> Vec<RequiredAnswerSection> {
    let mut seen = BTreeSet::new();
    infer_report_sections(query)
        .into_iter()
        .filter_map(|kind| {
            let key = report_section_key(kind).to_string();
            if key.is_empty() || !seen.insert(key.clone()) {
                return None;
            }
            Some(RequiredAnswerSection {
                key,
                label: report_section_label(kind, query),
                required: true,
            })
        })
        .collect()
}

pub(crate) fn section_kind_from_key(key: &str) -> Option<ReportSectionKind> {
    let normalized = normalize_section_key(key);
    if let Some(kind) = [
        ReportSectionKind::Summary,
        ReportSectionKind::RecentChange,
        ReportSectionKind::Significance,
        ReportSectionKind::UserImpact,
        ReportSectionKind::Mitigation,
        ReportSectionKind::EtaConfidence,
        ReportSectionKind::Caveat,
        ReportSectionKind::Evidence,
    ]
    .into_iter()
    .find(|kind| normalized == report_section_key(*kind))
    {
        return Some(kind);
    }
    [
        ReportSectionKind::Summary,
        ReportSectionKind::RecentChange,
        ReportSectionKind::Significance,
        ReportSectionKind::UserImpact,
        ReportSectionKind::Mitigation,
        ReportSectionKind::EtaConfidence,
        ReportSectionKind::Caveat,
        ReportSectionKind::Evidence,
    ]
    .into_iter()
    .find(|kind| {
        normalized == report_section_key(*kind)
            || report_section_aliases(*kind)
                .iter()
                .any(|alias| normalize_section_key(alias) == normalized)
    })
}

#[cfg(test)]
pub(crate) async fn synthesize_web_pipeline_reply_direct(
    service: &RuntimeAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> Option<String> {
    let _ = reason;
    let query = synthesis_query_contract(pending);
    let source_context = direct_source_context_from_pending(pending)?;
    let market_quote_rule = if query_requires_market_quote_grounding(&query) {
        "- For live market values, use only evidence text below that explicitly names the same asset and states the value. Do not say a value was unavailable when that value appears in the evidence text.\n"
    } else {
        ""
    };
    let comparison_guidance = direct_synthesis_behavior_guidance(&query);
    let prompt = format!(
        "Use the retrieved source notes to answer the user's question directly. \
		The runtime has already searched/read these sources; do not claim you lack browsing.\n\
Return only the final user-facing Markdown answer.\n\
Rules:\n\
- Be complete enough to answer the actual question; avoid filler.\n\
- Do not expose tool payloads, trace ids, fixture names, daemon details, or receipt language.\n\
- Do not use `Story 1`, `Story 2`, source-list pseudo-answer headings, or retrieval-summary scaffolding.\n\
- Do not use `Briefing for`, `What happened:`, `Key evidence:`, or any fixed report template.\n\
	- If the question asks for a comparison or recommendation, make a cautious call and explain uncertainty.\n\
		- For finance/investment questions, say this is not financial advice.\n\
		- For current finance/investment comparisons, do not state a live/current price unless a retrieved source note for that same asset contains an explicit quote/price. Do not treat forecast, opinion, or comparison-article numbers as live quotes.\n\
	{}\
	{}\
			- Include `Sources:` with Markdown links for the URLs used.\n\
			- If you use hidden thinking internally, write the final answer outside any <think> block.\n\
			- Do not print run dates, run timestamps, confidence labels, trace labels, or retrieval metadata; those are recorded separately.\n\n\
		User question: {}\n\n\
		Retrieved source notes:\n{}",
        market_quote_rule,
        comparison_guidance,
        query,
        source_context
    );
    let options = direct_synthesis_options(&query);
    let answer = run_visible_direct_synthesis(
        service,
        pending,
        "web_pipeline_direct_sourced_answer",
        &prompt,
        options.clone(),
    )
    .await;
    if answer.is_some() {
        return answer;
    }

    let retry_prompt = format!(
        "/no_think\n{prompt}\n\n\
The previous completion did not produce visible final answer text. \
Write the final user-facing answer now, outside any <think> block, preserve any current/latest/today qualifier from the user question, and include Markdown source links."
    );
    run_visible_direct_synthesis(
        service,
        pending,
        "web_pipeline_direct_sourced_answer_retry",
        &retry_prompt,
        options,
    )
    .await
}

fn direct_synthesis_options(query: &str) -> InferenceOptions {
    InferenceOptions {
        tools: vec![],
        temperature: 0.3,
        json_mode: false,
        max_tokens: direct_synthesis_max_tokens(&query),
        stop_sequences: Vec::new(),
        required_finality_tier: Default::default(),
        sealed_finality_proof: None,
        canonical_collapse_object: None,
    }
}

async fn run_visible_direct_synthesis(
    service: &RuntimeAgentService,
    pending: &PendingSearchCompletion,
    inference_label: &str,
    prompt: &str,
    options: InferenceOptions,
) -> Option<String> {
    let airlocked_prompt = service
        .prepare_cloud_inference_input(None, "desktop_agent", inference_label, prompt.as_bytes())
        .await
        .ok()?;
    let raw = match tokio::time::timeout(
        grounded_answer_timeout(),
        service
            .reasoning_inference
            .execute_inference([0u8; 32], &airlocked_prompt, options),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) | Err(_) => return None,
    };
    let answer = String::from_utf8(raw).ok()?;
    visible_direct_answer_from_raw(&answer, pending)
}

fn direct_contract_retry_feedback(facts: &FinalWebCompletionFacts) -> Vec<&'static str> {
    let mut feedback = Vec::new();
    if !facts.answer_legacy_source_cluster_headers_absent {
        feedback.push("remove retrieval scaffolding and story-style labels");
    }
    if !facts.evidence_citation_read_backing_floor_met
        || !facts.single_snapshot_rendered_read_backed_url_floor_met
    {
        feedback.push("cite the read sources that support the answer");
    }
    if !facts.evidence_selected_source_identifier_coverage_floor_met {
        feedback.push("tie cited sources to the named subject or asset they support");
    }
    if facts.market_quote_grounding_required && !facts.market_quote_grounding_floor_met {
        feedback.push("use explicit live market values only from evidence text for the same asset");
    }
    if facts.comparison_required && !facts.comparison_ready {
        feedback.push("answer the comparison directly instead of listing sources only");
    }
    if feedback.is_empty() {
        feedback.push("rewrite the answer naturally using only the supplied evidence");
    }
    feedback
}

async fn synthesize_web_pipeline_reply_direct_contract_retry(
    service: &RuntimeAgentService,
    pending: &PendingSearchCompletion,
    _reason: WebPipelineCompletionReason,
    previous_answer: &str,
    facts: &FinalWebCompletionFacts,
) -> Option<String> {
    let query = synthesis_query_contract(pending);
    let source_context = direct_source_context_from_pending(pending)?;
    let feedback = direct_contract_retry_feedback(facts).join("; ");
    let prompt = format!(
        "/no_think\n\
The previous final answer reached the runtime answer boundary but did not pass it. \
Rewrite a natural, user-facing Markdown answer. Do not mention this boundary or the feedback.\n\
Feedback: {feedback}.\n\
Rules:\n\
- Use only the source evidence below.\n\
- Do not expose tool payloads, trace ids, fixture names, daemon details, receipt language, or retrieval scaffolding.\n\
- Do not print run dates, run timestamps, confidence labels, trace labels, or retrieval metadata.\n\
- Preserve current/latest/today/right-now wording when the user asked for it.\n\
- If this is a finance or investment answer, say it is not financial advice.\n\
- Include `Sources:` with Markdown links for the URLs used.\n\n\
User question: {query}\n\n\
Previous answer:\n{previous_answer}\n\n\
Source evidence:\n{source_context}"
    );
    run_visible_direct_synthesis(
        service,
        pending,
        "web_pipeline_direct_sourced_answer_contract_retry",
        &prompt,
        direct_synthesis_options(&query),
    )
    .await
}

#[cfg(test)]
#[path = "grounded_answer/tests.rs"]
mod tests;
