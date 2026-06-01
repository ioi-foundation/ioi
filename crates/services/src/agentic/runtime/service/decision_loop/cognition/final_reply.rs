use crate::agentic::runtime::types::{AgentState, PendingSearchCompletion};
use ioi_types::app::agentic::{ChatMessage, IntentScopeProfile};
use ioi_types::app::ActionTarget;
use serde_json::{json, Value};

use super::history::build_recent_session_events_context;
use super::FINAL_REPLY_REPAIR_ATTEMPTS;

pub(super) fn web_context_ready_for_reply(
    agent_state: &AgentState,
    resolved_scope: IntentScopeProfile,
) -> bool {
    let Some(pending) = agent_state.pending_search_completion.as_ref() else {
        return false;
    };
    if queued_web_retrieve_count(agent_state) > 0 {
        return false;
    }
    if final_reply_pending_market_quote_ready(pending, &agent_state.goal) {
        return true;
    }
    let query_contract = crate::agentic::runtime::service::queue::synthesis_query_contract(pending);
    let required_source_cluster_floor =
        crate::agentic::runtime::service::queue::retrieval_contract_required_source_cluster_count(
            pending.retrieval_contract.as_ref(),
            &query_contract,
        )
        .max(1);
    if crate::agentic::runtime::service::queue::market_quote_grounding_contract_ready_for_pending(
        pending,
        &query_contract,
        crate::agentic::runtime::service::queue::query_requests_comparison(&query_contract),
        required_source_cluster_floor,
    ) {
        return true;
    }
    let required_sources = pending.min_sources.max(1) as usize;
    let enough_reads = pending.successful_reads.len() >= required_sources;
    enough_reads
        || (matches!(
            resolved_scope,
            IntentScopeProfile::WebResearch | IntentScopeProfile::Unknown
        ) && !pending.successful_reads.is_empty())
}

fn queued_web_retrieve_count(agent_state: &AgentState) -> usize {
    agent_state
        .execution_queue
        .iter()
        .filter(|request| request.target == ActionTarget::WebRetrieve)
        .count()
}

pub(super) fn final_reply_pending_market_quote_ready(
    pending: &PendingSearchCompletion,
    goal: &str,
) -> bool {
    let Some(context) = final_reply_market_quote_context_from_pending(pending, goal) else {
        return false;
    };
    final_reply_market_quote_context_metric_score(&context) >= 4
}

pub(crate) fn sanitize_direct_chat_reply_output(raw_output: &str) -> String {
    let mut text = raw_output.to_string();
    loop {
        let lower = text.to_ascii_lowercase();
        let Some(start) = lower.find("<think") else {
            break;
        };
        let after_open = lower[start..]
            .find('>')
            .map(|offset| start + offset + 1)
            .unwrap_or(start);
        let end = lower[after_open..]
            .find("</think>")
            .map(|offset| after_open + offset + "</think>".len())
            .unwrap_or_else(|| text.len());
        text.replace_range(start..end, "");
    }
    let text = text.trim().to_string();
    let unwrapped = unwrap_direct_chat_reply_json(&text).unwrap_or(text);
    collapse_repeated_final_reply_cycles(&unwrapped)
}

fn unwrap_direct_chat_reply_json(text: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    let name = value.get("name").and_then(Value::as_str).unwrap_or("");
    if name != "chat__reply" {
        return None;
    }
    value
        .get("arguments")
        .and_then(|arguments| arguments.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(str::to_string)
}

fn collapse_repeated_final_reply_cycles(text: &str) -> String {
    let mut current = text.trim().to_string();
    for _ in 0..4 {
        let char_count = current.chars().count();
        if char_count < 500 {
            break;
        }
        let Some(cut_at) = repeated_final_reply_cycle_cut_index(&current) else {
            break;
        };
        if cut_at < 240 || cut_at >= current.len() {
            break;
        }
        current.truncate(cut_at);
        current = current.trim_end().to_string();
    }
    current
}

fn repeated_final_reply_cycle_cut_index(text: &str) -> Option<usize> {
    let exact_prefix: String = text.chars().take(180).collect();
    if exact_prefix.chars().count() >= 80 {
        let search_start = exact_prefix.len();
        if let Some(offset) = text[search_start..].find(&exact_prefix) {
            let cut_at = search_start + offset;
            if cut_at + exact_prefix.len() < text.len() {
                return Some(cut_at);
            }
        }
    }

    let anchor = repeated_final_reply_cycle_anchor(text)?;
    let search_start = anchor.len();
    let lower_text = text.to_ascii_lowercase();
    let lower_anchor = anchor.to_ascii_lowercase();
    let offset = lower_text[search_start..].find(&lower_anchor)?;
    Some(search_start + offset)
}

fn repeated_final_reply_cycle_anchor(text: &str) -> Option<String> {
    let mut anchor = String::new();
    for ch in text.chars() {
        anchor.push(ch);
        if anchor.chars().count() >= 120 {
            break;
        }
        if matches!(ch, '.' | '!' | '?') && anchor.chars().count() >= 72 {
            break;
        }
    }
    let anchor = anchor.trim();
    if anchor.chars().count() < 72 {
        return None;
    }
    Some(anchor.to_string())
}

pub(super) fn final_reply_incomplete_reason(message: &str) -> Option<&'static str> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return Some("empty");
    }

    let fence_count = trimmed.matches("```").count();
    if fence_count % 2 != 0 {
        return Some("unclosed_code_fence");
    }

    let bold_count = trimmed.matches("**").count();
    if bold_count % 2 != 0 {
        return Some("unclosed_markdown_bold");
    }

    let last_line = trimmed.lines().last().unwrap_or(trimmed).trim();
    if matches!(
        last_line.chars().last(),
        Some(',' | ';' | ':' | '-' | '(' | '[' | '{' | '/')
    ) {
        return Some("dangling_terminal");
    }
    if matches!(last_line, "*" | "-" | "•") {
        return Some("dangling_list_marker");
    }

    None
}

pub(super) fn final_reply_goal_requests_html_document(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    let asks_to_create = [
        "create", "build", "generate", "make", "output", "write", "draft",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let asks_for_html = [
        "html",
        "website",
        "web site",
        "webpage",
        "web page",
        "landing page",
        "single-file page",
        "single file page",
    ]
    .iter()
    .any(|marker| lower.contains(marker));

    asks_to_create && asks_for_html
}

pub(super) fn final_reply_html_document_reason(message: &str, goal: &str) -> Option<&'static str> {
    if !final_reply_goal_requests_html_document(goal) {
        return None;
    }

    let trimmed = message.trim_start();
    if trimmed.is_empty() {
        return Some("empty_html_document");
    }

    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("<!doctype html") || lower.starts_with("<html")) {
        return Some("missing_html_document_start");
    }
    if !lower.contains("<body") {
        return Some("missing_html_body");
    }
    if !lower.trim_end().ends_with("</html>") {
        return Some("incomplete_html_document");
    }

    None
}

pub(super) fn final_reply_html_document_repair_messages(
    goal: &str,
    evidence_context: &str,
    reason: &str,
    attempt: usize,
) -> Value {
    json!([
        {
            "role": "system",
            "content": "SOURCE DOCUMENT COMPLETION MODE:\nWrite a fresh, complete, self-contained HTML document that satisfies the user's request using the gathered evidence where useful. Do not call tools. Do not output JSON. Do not wrap the answer in Markdown fences. Do not add explanatory prose before or after the document. Start exactly with <!DOCTYPE html> and end exactly with </html>. Keep the document concise enough to finish in one pass while still looking polished."
        },
        {
            "role": "user",
            "content": format!(
                "Original user request:\n{goal}\n\nGathered evidence:\n{evidence_context}\n\nThe previous source-document attempt was invalid ({reason}). Repair attempt {attempt} of {FINAL_REPLY_REPAIR_ATTEMPTS}: write the complete HTML document now."
            )
        }
    ])
}

pub(super) fn final_reply_evidence_contradiction_reason(
    message: &str,
    evidence_context: &str,
    goal: &str,
) -> Option<&'static str> {
    let goal_lower = goal.to_ascii_lowercase();
    if ![
        "investment",
        "invest",
        "price",
        "market cap",
        "marketcap",
        "trading",
        "quote",
        "token",
        "crypto",
    ]
    .iter()
    .any(|marker| goal_lower.contains(marker))
    {
        return None;
    }
    let evidence_lower = evidence_context.to_ascii_lowercase();
    if !market_quote_context_present(&evidence_lower) {
        return None;
    }

    let message_lower = message.to_ascii_lowercase();
    for unsupported_claim in [
        "no comparable data",
        "no comparable live",
        "no comparable price",
        "did not return live price",
        "did not retrieve live price",
        "did not include specific live price",
        "only asset with confirmed",
        "would require a separate price check",
        "not possible based on the current evidence",
        "market cap is not explicitly listed",
        "market cap is not explicitly provided",
        "market cap was not provided",
        "market cap is not provided",
        "market cap not provided",
        "no price, market cap",
        "no corresponding price, market cap",
        "no corresponding price",
        "no corresponding market",
        "no corresponding performance",
        "data was not retrieved",
        "no price data was retrieved",
        "no market data was retrieved",
        "no performance data was retrieved",
        "no price data was found",
        "no market data was found",
        "no performance data was found",
        "no price, market cap, or performance data was found",
        "specific current price data for",
        "do not contain specific live price quotes",
        "do not contain specific live price quotes or market cap data",
        "do not provide any live price quotes",
        "do not provide live price quotes",
        "search results do not provide any live price quotes",
        "search results do not provide live price quotes",
        "without current valuation data",
        "without specific price data for",
        "lack of current price data",
        "lack of current price data in the evidence",
        "no specific price data",
    ] {
        if message_lower.contains(unsupported_claim) {
            return Some("contradicts_typed_market_quote_evidence");
        }
    }

    if nominal_price_investment_quality_misuse(&message_lower) {
        return Some("infers_investment_quality_from_nominal_token_price");
    }

    if contains_unsupported_market_scale_metric(&evidence_lower, &message_lower) {
        return Some("unsupported_market_quote_metric");
    }

    None
}

fn nominal_price_investment_quality_misuse(message_lower: &str) -> bool {
    let direct_bad_phrases = [
        "primarily due to its higher price point",
        "primarily due to its lower price point",
        "because of its higher price point",
        "because of its lower price point",
        "because it has a higher price point",
        "because it has a lower price point",
        "because of its higher per-token price",
        "because of its lower per-token price",
        "due to its higher per-token price",
        "due to its lower per-token price",
        "lower entry price",
        "accessible entry point",
        "entry point for investors",
        "lower price point makes it",
        "higher price point makes it",
        "lower per-token price makes it",
        "higher per-token price makes it",
    ];
    if direct_bad_phrases
        .iter()
        .any(|phrase| message_lower.contains(phrase))
    {
        return true;
    }

    let recommendation_surface = [
        "stronger investment",
        "better investment",
        "better choice",
        "better option",
        "safer bet",
        "choose akash",
        "choose filecoin",
    ]
    .iter()
    .any(|claim| message_lower.contains(claim));
    if !recommendation_surface {
        return false;
    }

    let causal_price_surface = [
        "due to its higher price",
        "due to its lower price",
        "because of its higher price",
        "because of its lower price",
        "as it has a higher price",
        "as it has a lower price",
        "since it has a higher price",
        "since it has a lower price",
    ]
    .iter()
    .any(|phrase| message_lower.contains(phrase));
    causal_price_surface
}

pub(super) fn final_reply_evidence_contract_reason(
    message: &str,
    evidence_context: &str,
    goal: &str,
) -> Option<&'static str> {
    final_reply_evidence_contradiction_reason(message, evidence_context, goal)
        .or_else(|| final_reply_evidence_omission_reason(message, evidence_context, goal))
}

pub(super) fn final_reply_product_handoff_reason(
    message: &str,
    goal: &str,
) -> Option<&'static str> {
    if final_reply_goal_requests_raw_tool_output(goal) {
        return None;
    }

    let trimmed = message.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }

    if lower.contains("tool output (")
        || lower.contains("tool output:")
        || lower.contains("raw_output")
        || (lower.starts_with('{') && lower.contains("\"name\"") && lower.contains("\"arguments\""))
    {
        return Some("raw_tool_payload");
    }

    if lower.contains("tap version")
        && (lower.contains("# subtest")
            || lower.contains("# tests")
            || lower.contains("# pass")
            || lower.contains("duration_ms"))
    {
        return Some("raw_test_log_dump");
    }

    if (lower.contains("stdout:") || lower.contains("stderr:"))
        && (lower.contains("exited with code") || lower.starts_with("command "))
    {
        return Some("raw_command_output_dump");
    }

    None
}

fn final_reply_goal_requests_raw_tool_output(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    [
        "raw stdout",
        "raw stderr",
        "raw output",
        "full stdout",
        "full stderr",
        "full output",
        "paste stdout",
        "paste stderr",
        "show stdout",
        "show stderr",
        "show the log",
        "full log",
        "verbatim output",
        "tap output",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn final_reply_evidence_omission_reason(
    message: &str,
    evidence_context: &str,
    goal: &str,
) -> Option<&'static str> {
    let goal_lower = goal.to_ascii_lowercase();
    if ![
        "investment",
        "invest",
        "price",
        "market cap",
        "trading",
        "quote",
        "right now",
        "current",
    ]
    .iter()
    .any(|marker| goal_lower.contains(marker))
    {
        return None;
    }
    let evidence_lower = evidence_context.to_ascii_lowercase();
    if !market_quote_context_present(&evidence_lower) {
        return None;
    }
    let message_lower = message.to_ascii_lowercase();
    if final_reply_metric_groups_omitted(&evidence_lower, &message_lower, "market cap:") {
        return Some("omits_typed_market_quote_market_caps");
    }
    if final_reply_metric_groups_omitted(&evidence_lower, &message_lower, "24h trading volume:") {
        return Some("omits_typed_market_quote_volumes");
    }
    None
}

fn final_reply_metric_groups_omitted(
    evidence_lower: &str,
    message_lower: &str,
    label: &str,
) -> bool {
    let marker_groups = final_reply_metric_marker_groups(evidence_lower, label);
    if marker_groups.len() < 2 {
        return false;
    }
    final_reply_metric_marker_groups_represented(&marker_groups, message_lower) < 2
}

pub(super) fn final_reply_market_quote_context_metric_score(context: &str) -> usize {
    let lower = context.to_ascii_lowercase();
    final_reply_metric_marker_groups(&lower, "market cap:").len()
        + final_reply_metric_marker_groups(&lower, "24h trading volume:").len()
}

fn contains_unsupported_market_scale_metric(evidence_lower: &str, message_lower: &str) -> bool {
    if !market_quote_context_present(&evidence_lower) {
        return false;
    }

    let mut supported = final_reply_metric_marker_groups(evidence_lower, "market cap:")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    supported.extend(
        final_reply_metric_marker_groups(evidence_lower, "24h trading volume:")
            .into_iter()
            .flatten(),
    );
    supported.sort();
    supported.dedup();
    if supported.is_empty() {
        return false;
    }

    unsupported_market_scale_metrics(message_lower)
        .into_iter()
        .any(|metric| !supported.iter().any(|marker| marker == &metric))
}

fn unsupported_market_scale_metrics(message_lower: &str) -> Vec<String> {
    let mut metrics = Vec::new();
    let bytes = message_lower.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len()
            && (bytes[index].is_ascii_digit() || bytes[index] == b'.' || bytes[index] == b',')
        {
            index += 1;
        }
        if index == start + 1 {
            continue;
        }
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let unit_start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
            index += 1;
        }
        let unit = &message_lower[unit_start..index];
        let Some(normalized_unit) = normalize_market_scale_unit(unit) else {
            continue;
        };
        let number = message_lower[start + 1..unit_start].trim().replace(',', "");
        if number.is_empty() {
            continue;
        }
        metrics.push(format!("${number}{normalized_unit}"));
    }
    metrics.sort();
    metrics.dedup();
    metrics
}

fn normalize_market_scale_unit(unit: &str) -> Option<&'static str> {
    match unit {
        "m" | "mn" | "mil" | "million" => Some("m"),
        "b" | "bn" | "bil" | "billion" => Some("b"),
        _ => None,
    }
}

fn final_reply_metric_marker_groups(evidence_lower: &str, label: &str) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    let mut offset = 0usize;
    while offset < evidence_lower.len() {
        let Some(relative) = evidence_lower[offset..].find(label) else {
            break;
        };
        let start = offset + relative;
        if let Some(markers) = final_reply_metric_marker_set(&evidence_lower[start..], label) {
            groups.push(markers);
        }
        offset = start.saturating_add(label.len());
    }
    groups
}

fn final_reply_metric_marker_groups_represented(
    marker_groups: &[Vec<String>],
    message_lower: &str,
) -> usize {
    marker_groups
        .iter()
        .filter(|markers| {
            markers
                .iter()
                .any(|marker| message_lower.contains(marker.as_str()))
        })
        .count()
}

fn final_reply_metric_marker_set(text: &str, label: &str) -> Option<Vec<String>> {
    let start = text.find(label)?;
    let after_label = &text[start + label.len()..];
    let dollar = after_label.find('$')?;
    let after_dollar = &after_label[dollar + 1..];
    let number = after_dollar
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == ',')
        .collect::<String>()
        .replace(',', "");
    let unit_tail = &after_dollar[after_dollar
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == ','))
        .unwrap_or(after_dollar.len())..];
    let value = number.parse::<f64>().ok()?;
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let unit = unit_tail.trim_start().chars().next().unwrap_or('m');
    let mut markers = if unit == 'b' {
        let whole_billions = value.floor() as u64;
        let one_decimal = format!("{value:.1}");
        let two_decimal = format!("{value:.2}");
        let whole_millions = (value * 1000.0).round() as u64;
        vec![
            format!("${two_decimal}b"),
            format!("${one_decimal}b"),
            format!("${whole_billions}b"),
            format!("{two_decimal}b"),
            format!("{one_decimal}b"),
            format!("${two_decimal} billion"),
            format!("${one_decimal} billion"),
            format!("{two_decimal} billion"),
            format!("{one_decimal} billion"),
            format!("${two_decimal}bn"),
            format!("${one_decimal}bn"),
            format!("{two_decimal}bn"),
            format!("{one_decimal}bn"),
            format!("${whole_millions}m"),
            format!("${whole_millions} million"),
            format!("{whole_millions}m"),
            format!("{whole_millions} million"),
        ]
    } else {
        let whole = value.floor() as u64;
        if whole == 0 {
            return None;
        }
        let rounded = value.round() as u64;
        let one_decimal = format!("{value:.1}");
        let two_decimal = format!("{value:.2}");
        let mut markers = vec![
            format!("${two_decimal}m"),
            format!("${one_decimal}m"),
            format!("${whole}m"),
            format!("{two_decimal}m"),
            format!("{one_decimal}m"),
            format!("{whole}m"),
            format!("${two_decimal} million"),
            format!("${one_decimal} million"),
            format!("${whole} million"),
            format!("{two_decimal} million"),
            format!("{one_decimal} million"),
            format!("{whole} million"),
        ];
        if rounded != whole {
            markers.push(format!("${rounded}m"));
            markers.push(format!("${rounded} million"));
            markers.push(format!("{rounded}m"));
            markers.push(format!("{rounded} million"));
        }
        markers
    };
    markers.sort();
    markers.dedup();
    Some(markers)
}

pub(super) fn final_reply_repair_messages(
    _messages: &Value,
    _previous_answer: &str,
    reason: &str,
    attempt: usize,
    goal: &str,
    evidence_context: &str,
) -> Value {
    json!([
        {
            "role": "system",
            "content": "FINAL RESPONSE REPAIR MODE:\nWrite a fresh user-facing answer from the gathered evidence only. Do not call tools. Do not output JSON. Do not expose hidden chain-of-thought, trace ids, receipt ids, raw payloads, raw stdout/stderr, raw test logs, or daemon scaffolding.\nFor command, test, and workspace-change tasks, summarize what changed or was inspected and whether verification passed; keep full logs in tracing unless the user explicitly requested raw logs. If you cite the final contents of a changed file or a short command-created source snippet, put it in a fenced code block with a language tag instead of appending it inline to a sentence. When gathered evidence contains repeated observations of the same file or state, use the latest/highest-numbered observation as authoritative for the current state.\nPreserve source anchors and observed measurements that matter. If current market quote observations are present for multiple assets, include the observed price, market cap, 24h trading volume, and 24h price change for each asset. Do not say those fields are missing when they are present in the gathered evidence.\nFor investment comparisons, synthesize a cautious comparison from the observed metrics and the gathered use-case/risk context. Treat per-token price only as a quote, not as an investment advantage by itself. If the evidence is incomplete, say exactly which non-observed dimensions remain uncertain. Do not copy internal evidence labels into the final answer."
        },
        {
            "role": "user",
            "content": format!(
                "Original user request:\n{goal}\n\nGathered evidence:\n{evidence_context}\n\nThe previous final answer was invalid ({reason}). Repair attempt {attempt} of {FINAL_REPLY_REPAIR_ATTEMPTS}: write the final natural Markdown answer now. The invalid draft is intentionally omitted so stale or invented numbers cannot be copied forward."
            )
        }
    ])
}

pub(super) fn final_reply_evidence_context(
    history: &[ChatMessage],
    goal: &str,
    fallback_context: &str,
) -> String {
    let mut candidates = Vec::<FinalReplyEvidenceCandidate>::new();
    let terms = significant_goal_terms(goal);
    let workspace_rollback_boundary = workspace_rollback_evidence_boundary(history);
    for (order, message) in history.iter().enumerate() {
        if message.role != "tool" {
            continue;
        }
        if workspace_rollback_boundary
            .map(|boundary| order <= boundary)
            .unwrap_or(false)
        {
            continue;
        }
        let content = message.content.trim();
        if content.is_empty()
            || content.contains("ERROR_CLASS=")
            || content.contains("Skipped immediate replay")
            || raw_workspace_change_payload(content)
        {
            continue;
        }
        if content.eq_ignore_ascii_case("Web evidence is ready for a model-authored final answer.")
            || content.starts_with("Queued grounded search recovery")
        {
            continue;
        }
        let web_evidence = web_tool_result_source_notes(content, goal);
        let is_web_evidence = web_evidence.is_some();
        let evidence =
            web_evidence.unwrap_or_else(|| extract_goal_relevant_evidence(content, goal, 8_000));
        let evidence = evidence.trim().to_string();
        if evidence.is_empty() {
            continue;
        }
        let score = final_reply_evidence_score(&evidence, &terms, is_web_evidence);
        if score <= 0 {
            continue;
        }
        candidates.push(FinalReplyEvidenceCandidate {
            order,
            evidence,
            is_web_evidence,
            score,
        });
    }

    let market_quote_context = final_reply_market_quote_context(history, goal)
        .or_else(|| final_reply_market_quote_context_from_text(fallback_context, goal));
    let has_market_quote_context = market_quote_context.is_some();

    let mut web_candidates = candidates
        .iter()
        .filter(|candidate| candidate.is_web_evidence)
        .cloned()
        .collect::<Vec<_>>();
    let mut other_candidates = candidates
        .iter()
        .filter(|candidate| !candidate.is_web_evidence)
        .cloned()
        .collect::<Vec<_>>();
    web_candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.order.cmp(&b.order)));
    other_candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.order.cmp(&b.order)));

    let mut selected = Vec::<FinalReplyEvidenceCandidate>::new();
    let web_candidate_limit = if has_market_quote_context { 8 } else { 12 };
    let other_candidate_limit = if has_market_quote_context { 2 } else { 4 };
    selected.extend(web_candidates.into_iter().take(web_candidate_limit));
    selected.extend(other_candidates.into_iter().take(other_candidate_limit));
    selected.sort_by_key(|candidate| candidate.order);

    let mut entries = Vec::<String>::new();
    let mut total_chars = 0usize;
    if let Some(market_quote_context) = market_quote_context {
        total_chars = total_chars.saturating_add(market_quote_context.chars().count());
        entries.push(market_quote_context);
    }
    for candidate in selected {
        let evidence = if candidate.is_web_evidence {
            format!(
                "Source observation #{}:\n{}",
                candidate.order.saturating_add(1),
                candidate.evidence
            )
        } else {
            format!(
                "Tool observation #{} (chronological; higher observation numbers are newer):\n{}",
                candidate.order.saturating_add(1),
                candidate.evidence
            )
        };
        let evidence_chars = evidence.chars().count();
        let evidence_budget = 24_000;
        if total_chars.saturating_add(evidence_chars) > evidence_budget && !entries.is_empty() {
            continue;
        }
        total_chars = total_chars.saturating_add(evidence_chars);
        entries.push(evidence);
    }
    if entries.is_empty() {
        fallback_context.to_string()
    } else {
        entries.join("\n\n---\n\n")
    }
}

fn final_reply_market_quote_context(history: &[ChatMessage], goal: &str) -> Option<String> {
    let goal_lower = goal.to_ascii_lowercase();
    if ![
        "investment",
        "invest",
        "price",
        "market cap",
        "trading",
        "quote",
        "right now",
        "current",
    ]
    .iter()
    .any(|marker| goal_lower.contains(marker))
    {
        return None;
    }

    let terms = significant_goal_terms(goal);
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut lines = Vec::<String>::new();
    for message in history {
        if message.role != "tool" {
            continue;
        }
        let Some(payload) = web_tool_payload_from_content(&message.content) else {
            continue;
        };
        let tool = payload.get("tool").and_then(Value::as_str).unwrap_or("");
        if tool != "web__read" && tool != "web__search" {
            continue;
        }

        if let Some(sources) = payload.get("sources").and_then(Value::as_array) {
            for source in sources {
                if let Some(line) = market_quote_line_from_json_source(source, &terms) {
                    let key = line.to_ascii_lowercase();
                    if seen.insert(key) {
                        lines.push(line);
                    }
                }
            }
        }
        if let Some(documents) = payload.get("documents").and_then(Value::as_array) {
            for document in documents {
                if let Some(line) = market_quote_line_from_json_source(document, &terms) {
                    let key = line.to_ascii_lowercase();
                    if seen.insert(key) {
                        lines.push(line);
                    }
                }
            }
        }
    }

    if lines.len() < 2
        && !lines
            .iter()
            .any(|line| goal_terms_appear_in_text(&terms, line))
    {
        return None;
    }
    if lines.is_empty() {
        return None;
    }

    Some(render_typed_market_quote_context(&lines))
}

pub(super) fn final_reply_market_quote_context_from_pending(
    pending: &PendingSearchCompletion,
    goal: &str,
) -> Option<String> {
    let goal_lower = goal.to_ascii_lowercase();
    if ![
        "investment",
        "invest",
        "price",
        "market cap",
        "trading",
        "quote",
        "right now",
        "current",
    ]
    .iter()
    .any(|marker| goal_lower.contains(marker))
    {
        return None;
    }

    let terms = significant_goal_terms(goal);
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut lines = Vec::<String>::new();
    for source in &pending.successful_reads {
        let value = json!({
            "title": source.title.as_deref().unwrap_or_default(),
            "url": source.url,
            "snippet": source.excerpt,
        });
        if let Some(line) = market_quote_line_from_json_source(&value, &terms) {
            let key = line.to_ascii_lowercase();
            if seen.insert(key) {
                lines.push(line);
            }
        }
    }

    if lines.is_empty() {
        return None;
    }

    Some(render_typed_market_quote_context(&lines))
}

pub(super) fn final_reply_pending_web_evidence_context(
    pending: &PendingSearchCompletion,
    goal: &str,
) -> Option<String> {
    let terms = significant_goal_terms(goal);
    let quote_context = final_reply_market_quote_context_from_pending(pending, goal);
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut lines = Vec::<String>::new();

    for source in pending.successful_reads.iter().take(12) {
        let title = source.title.as_deref().unwrap_or_default().trim();
        let url = source.url.trim();
        let excerpt = source.excerpt.trim();
        if url.is_empty() && title.is_empty() && excerpt.is_empty() {
            continue;
        }

        let lower = excerpt.to_ascii_lowercase();
        if final_reply_evidence_is_low_signal(&lower) {
            continue;
        }
        let excerpt_budget = if lower.contains("simple price api")
            || lower.contains("provider-supplied market data")
            || (lower.contains("price") && lower.contains("market cap"))
        {
            1_200
        } else {
            900
        };
        let excerpt = compact_relevant_excerpt(excerpt, &terms, excerpt_budget);
        let mut parts = Vec::new();
        if !title.is_empty() {
            parts.push(format!("Source: {title}"));
        }
        if !url.is_empty() {
            parts.push(format!("URL: {url}"));
        }
        if !excerpt.is_empty() {
            parts.push(format!("Observation: {excerpt}"));
        }
        if parts.is_empty() {
            continue;
        }
        let line = format!("- {}", parts.join(" | "));
        if seen.insert(line.to_ascii_lowercase()) {
            lines.push(line);
        }
    }

    let source_context = if lines.is_empty() {
        None
    } else {
        Some(format!(
            "Web observations from tool results:\n{}",
            lines.join("\n")
        ))
    };

    match (quote_context, source_context) {
        (Some(quote_context), Some(source_context)) => {
            if source_context.contains(quote_context.trim()) {
                Some(source_context)
            } else {
                Some(format!("{quote_context}\n\n---\n\n{source_context}"))
            }
        }
        (Some(quote_context), None) => Some(quote_context),
        (None, Some(source_context)) => Some(source_context),
        (None, None) => None,
    }
}

fn final_reply_market_quote_context_from_text(context: &str, goal: &str) -> Option<String> {
    let goal_lower = goal.to_ascii_lowercase();
    if ![
        "investment",
        "invest",
        "price",
        "market cap",
        "trading",
        "quote",
        "right now",
        "current",
    ]
    .iter()
    .any(|marker| goal_lower.contains(marker))
    {
        return None;
    }

    let terms = significant_goal_terms(goal);
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut lines = Vec::<String>::new();
    for segment in context.lines().flat_map(|line| line.split(" || ")) {
        let Some(line) = market_quote_line_from_text_segment(segment, &terms) else {
            continue;
        };
        let key = line.to_ascii_lowercase();
        if seen.insert(key) {
            lines.push(line);
        }
    }

    if lines.is_empty() {
        return None;
    }
    Some(render_typed_market_quote_context(&lines))
}

fn render_typed_market_quote_context(lines: &[String]) -> String {
    format!(
        "Current market quote observations from tool results:\n\
These observations came from quote-grade web tool outputs. If answering, include the observed metrics and do not say market cap, 24h volume, or 24h change are missing when they are present:\n{}",
        lines.join("\n")
    )
}

fn market_quote_context_present(evidence_lower: &str) -> bool {
    evidence_lower.contains("current market quote observations from tool results")
        || evidence_lower.contains("typed market quote evidence from tool results")
}

fn market_quote_line_from_text_segment(segment: &str, terms: &[String]) -> Option<String> {
    let segment = segment.split_whitespace().collect::<Vec<_>>().join(" ");
    if segment.is_empty() {
        return None;
    }

    let lower = segment.to_ascii_lowercase();
    let has_quote_signal = lower.contains("live usd quote")
        || lower.contains("simple price api")
        || lower.contains("provider-supplied market data")
        || (lower.contains("price") && lower.contains("market cap"));
    if !has_quote_signal {
        return None;
    }
    if !terms.is_empty() && !goal_terms_appear_in_text(terms, &segment) {
        return None;
    }

    let mut title = String::new();
    let mut url = String::new();
    let mut evidence_parts = Vec::<String>::new();
    for part in segment
        .split(" | ")
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
    {
        if part.starts_with("http://") || part.starts_with("https://") {
            if url.is_empty() {
                url = part.to_string();
            }
            continue;
        }

        let cleaned_title = strip_recent_session_web_summary_prefix(part);
        let part_lower = part.to_ascii_lowercase();
        if part_lower.contains("live usd quote")
            || part_lower.contains("simple price api")
            || part_lower.contains("provider-supplied market data")
            || (part_lower.contains("price") && part_lower.contains("market cap"))
        {
            evidence_parts.push(part.to_string());
        } else if title.is_empty() && !cleaned_title.is_empty() {
            title = cleaned_title;
        }
    }

    let evidence_storage;
    let evidence = if evidence_parts.is_empty() {
        segment.as_str()
    } else {
        evidence_storage = evidence_parts.join(" | ");
        evidence_storage.as_str()
    };
    if let Some(normalized_quote) = normalized_market_quote_line(&title, &url, evidence) {
        return Some(format!("- {normalized_quote}"));
    }

    let evidence = compact_relevant_excerpt(evidence, terms, 900);
    if evidence.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !title.is_empty() {
        parts.push(title);
    }
    parts.push(evidence);
    if !url.is_empty() {
        parts.push(format!("source: {url}"));
    }
    Some(format!("- {}", parts.join(" | ")))
}

fn strip_recent_session_web_summary_prefix(value: &str) -> String {
    let mut cleaned = value.trim();
    for marker in ["sources=", "docs="] {
        if let Some((_, tail)) = cleaned.rsplit_once(marker) {
            cleaned = tail.trim();
        }
    }
    if let Some((_, tail)) = cleaned.rsplit_once(" ; ") {
        let tail = tail.trim();
        if !tail.starts_with("http://") && !tail.starts_with("https://") {
            cleaned = tail;
        }
    }
    cleaned
        .strip_prefix("tool:")
        .unwrap_or(cleaned)
        .trim()
        .to_string()
}

fn market_quote_line_from_json_source(value: &Value, terms: &[String]) -> Option<String> {
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let url = value
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let text = value
        .get("snippet")
        .or_else(|| value.get("content_text"))
        .or_else(|| value.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if text.is_empty() {
        return None;
    }

    let lower = text.to_ascii_lowercase();
    let has_quote_signal = lower.contains("live usd quote")
        || lower.contains("simple price api")
        || lower.contains("provider-supplied market data")
        || (lower.contains("price") && lower.contains("market cap"));
    if !has_quote_signal {
        return None;
    }

    let combined = format!("{title} {url} {text}");
    if !terms.is_empty() && !goal_terms_appear_in_text(terms, &combined) {
        return None;
    }

    if let Some(normalized_quote) = normalized_market_quote_line(title, url, text) {
        return Some(format!("- {normalized_quote}"));
    }

    let evidence = if lower.contains("simple price api")
        || lower.contains("provider-supplied market data")
        || (lower.contains("market cap:") && lower.contains("24h trading volume:"))
    {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(1200)
            .collect::<String>()
    } else {
        compact_relevant_excerpt(text, terms, 700)
    };
    if evidence.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !title.is_empty() {
        parts.push(title.to_string());
    }
    parts.push(evidence);
    if !url.is_empty() {
        parts.push(format!("source: {url}"));
    }
    Some(format!("- {}", parts.join(" | ")))
}

fn normalized_market_quote_line(title: &str, url: &str, text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if !(lower.contains("simple price api")
        || lower.contains("provider-supplied market data")
        || (lower.contains("market cap:") && lower.contains("24h trading volume:")))
    {
        return None;
    }

    let price = dollar_value_after_marker(text, "price")?;
    let market_cap = dollar_value_after_marker(text, "market cap:")?;
    let volume = dollar_value_after_marker(text, "24h trading volume:")?;
    let change = percent_value_after_marker(text, "24h price change:");
    let asset = market_quote_asset_label(title, text);

    let mut parts = vec![
        asset,
        format!("price: {price}"),
        format!("market cap: {market_cap}"),
        format!("24h trading volume: {volume}"),
    ];
    if let Some(change) = change {
        parts.push(format!("24h price change: {change}"));
    }
    if !title.trim().is_empty() {
        parts.push(format!("source title: {}", title.trim()));
    }
    if !url.trim().is_empty() {
        parts.push(format!("source URL: {}", url.trim()));
    }
    Some(parts.join("; "))
}

fn market_quote_asset_label(title: &str, text: &str) -> String {
    let title = title.trim();
    if !title.is_empty() {
        for suffix in [
            " live USD price quote - CoinGecko",
            " live usd price quote - coingecko",
            " Price: ",
            " price today",
        ] {
            if let Some(stripped) = title.strip_suffix(suffix) {
                let stripped = stripped.trim();
                if !stripped.is_empty() {
                    return stripped.to_string();
                }
            }
        }
        return title.to_string();
    }

    let text = text.trim();
    if let Some(open) = text.find(" (") {
        let candidate = text[..open].trim();
        if !candidate.is_empty() {
            return candidate.to_string();
        }
    }
    "market asset".to_string()
}

fn dollar_value_after_marker(text: &str, marker: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    let marker_index = lower.find(&marker_lower)?;
    let after_marker = &text[marker_index + marker.len()..];
    let dollar_index = after_marker.find('$')?;
    let after_dollar = &after_marker[dollar_index + 1..];
    let number = after_dollar
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == ',')
        .collect::<String>();
    if number.is_empty() {
        return None;
    }
    let unit = after_dollar[number.len()..]
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .collect::<String>();
    let unit = if unit.eq_ignore_ascii_case("usd") {
        String::new()
    } else {
        unit
    };
    if unit.is_empty() {
        Some(format!("${number}"))
    } else {
        Some(format!("${number}{unit}"))
    }
}

fn percent_value_after_marker(text: &str, marker: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    let marker_index = lower.find(&marker_lower)?;
    let after_marker = &text[marker_index + marker.len()..];
    let percent_index = after_marker.find('%')?;
    let before_percent = &after_marker[..percent_index];
    let number_start = before_percent
        .rfind(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == '-' || ch == '+'))
        .map(|index| index + 1)
        .unwrap_or(0);
    let number = before_percent[number_start..].trim();
    if number.is_empty() {
        return None;
    }
    Some(format!("{number}%"))
}

fn goal_terms_appear_in_text(terms: &[String], text: &str) -> bool {
    if terms.is_empty() {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    terms.iter().any(|term| lower.contains(term))
}

#[derive(Clone)]
struct FinalReplyEvidenceCandidate {
    order: usize,
    evidence: String,
    is_web_evidence: bool,
    score: i32,
}

fn raw_workspace_change_payload(content: &str) -> bool {
    content.contains("\"change_id\"")
        && content.contains("\"lifecycle\"")
        && (content.contains("\"hunks\"")
            || content.contains("\"search_text\"")
            || content.contains("\"replace_text\""))
}

fn workspace_rollback_evidence_boundary(history: &[ChatMessage]) -> Option<usize> {
    history
        .iter()
        .enumerate()
        .rev()
        .find_map(|(order, message)| {
            if message.role != "tool" {
                return None;
            }
            let content = message.content.trim();
            if raw_workspace_change_payload(content)
                && content.contains("\"workspace_change:")
                && content.contains("\"rolled_back\"")
            {
                Some(order)
            } else {
                None
            }
        })
}

fn final_reply_evidence_score(evidence: &str, terms: &[String], is_web_evidence: bool) -> i32 {
    let lower = evidence.to_ascii_lowercase();
    if final_reply_evidence_is_low_signal(&lower) {
        return 0;
    }

    let mut score = if is_web_evidence { 8 } else { 4 };
    for term in terms {
        if lower.contains(term) {
            score += 6;
        }
    }
    if lower.contains("http://") || lower.contains("https://") {
        score += 3;
    }
    if lower.contains('$') {
        score += 10;
    }
    if lower.contains('%') {
        score += 5;
    }
    for marker in [
        "price",
        "market cap",
        "trading volume",
        "24h",
        "live usd",
        "quote",
        "coingecko",
        "coinmarketcap",
        "crypto.com",
        "source",
        "citation",
    ] {
        if lower.contains(marker) {
            score += 4;
        }
    }
    if lower.contains("simple price api") || lower.contains("provider-supplied market data") {
        score += 12;
    }
    score
}

fn final_reply_evidence_is_low_signal(lower: &str) -> bool {
    [
        "challenge verification",
        "cf_chl_opt",
        "cdn-cgi/challenge-platform",
        "the requested page could not be found",
        "content_text\": \"\"",
        "empty source lists",
        "source_count\": 0",
        "duckduckgo anomaly",
        "browser retrieval navigate failed",
        "no specific ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn web_tool_result_source_notes(content: &str, goal: &str) -> Option<String> {
    let value = web_tool_payload_from_content(content)?;
    let tool = value.get("tool").and_then(Value::as_str).unwrap_or("");
    if tool != "web__search" && tool != "web__read" {
        return None;
    }

    let mut notes = Vec::<String>::new();
    let query = value
        .get("query")
        .and_then(Value::as_str)
        .or_else(|| value.get("url").and_then(Value::as_str))
        .unwrap_or("")
        .trim();
    if !query.is_empty() {
        notes.push(format!("Web observation from {tool} for {query}:"));
    } else {
        notes.push(format!("Web observation from {tool}:"));
    }

    let terms = significant_goal_terms(goal);
    let mut seen = std::collections::BTreeSet::<String>::new();
    if let Some(sources) = value.get("sources").and_then(Value::as_array) {
        for source in sources.iter().take(8) {
            let Some(note) = source_note_from_json(source, &terms) else {
                continue;
            };
            let key = note.to_ascii_lowercase();
            if seen.insert(key) {
                notes.push(note);
            }
        }
    }

    if let Some(documents) = value.get("documents").and_then(Value::as_array) {
        for document in documents.iter().take(4) {
            let Some(note) = document_note_from_json(document, &terms) else {
                continue;
            };
            let key = note.to_ascii_lowercase();
            if seen.insert(key) {
                notes.push(note);
            }
        }
    }

    if notes.len() <= 1 {
        return None;
    }

    Some(truncate_final_reply_evidence(&notes.join("\n"), 8_000))
}

fn parse_embedded_json_object(content: &str) -> Option<Value> {
    let trimmed = content.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Some(value);
    }
    let start = trimmed.find('{')?;
    let json_text = &trimmed[start..];
    serde_json::from_str::<Value>(json_text).ok()
}

fn web_tool_payload_from_content(content: &str) -> Option<Value> {
    let value = parse_embedded_json_object(content)?;
    extract_web_tool_payload(&value, 0)
}

fn extract_web_tool_payload(value: &Value, depth: usize) -> Option<Value> {
    if depth > 6 {
        return None;
    }
    let tool = value.get("tool").and_then(Value::as_str).unwrap_or("");
    if tool == "web__search" || tool == "web__read" {
        return Some(value.clone());
    }

    for pointer in [
        "/AgentActionResult/output",
        "/agent_action_result/output",
        "/kernel_event/AgentActionResult/output",
        "/payload/AgentActionResult/output",
        "/payload/kernel_event/AgentActionResult/output",
        "/payload_summary/AgentActionResult/output",
        "/payload_summary/kernel_event/AgentActionResult/output",
    ] {
        if let Some(output) = value.pointer(pointer) {
            if let Some(payload) = extract_web_tool_payload_candidate(output, depth + 1) {
                return Some(payload);
            }
        }
    }

    for key in [
        "payload",
        "payload_summary",
        "kernel_event",
        "AgentActionResult",
        "agent_action_result",
        "result",
        "data",
        "preview",
    ] {
        if let Some(candidate) = value.get(key) {
            if let Some(payload) = extract_web_tool_payload_candidate(candidate, depth + 1) {
                return Some(payload);
            }
        }
    }

    None
}

fn extract_web_tool_payload_candidate(candidate: &Value, depth: usize) -> Option<Value> {
    if depth > 6 {
        return None;
    }
    if let Some(text) = candidate.as_str() {
        return parse_embedded_json_object(text)
            .and_then(|value| extract_web_tool_payload(&value, depth + 1));
    }
    if candidate.is_object() {
        return extract_web_tool_payload(candidate, depth + 1);
    }
    None
}

fn source_note_from_json(source: &Value, terms: &[String]) -> Option<String> {
    let title = source
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let url = source
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let domain = source
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let snippet = source
        .get("snippet")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if title.is_empty() && url.is_empty() && snippet.is_empty() {
        return None;
    }

    let evidence = compact_relevant_excerpt(snippet, terms, 900);
    let mut parts = Vec::new();
    if !title.is_empty() {
        parts.push(format!("Source: {title}"));
    }
    if !url.is_empty() {
        parts.push(format!("URL: {url}"));
    } else if !domain.is_empty() {
        parts.push(format!("Domain: {domain}"));
    }
    if !evidence.is_empty() {
        parts.push(format!("Observation: {evidence}"));
    }
    Some(format!("- {}", parts.join(" | ")))
}

fn document_note_from_json(document: &Value, terms: &[String]) -> Option<String> {
    let title = document
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let url = document
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let content = document
        .get("content_text")
        .or_else(|| document.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if title.is_empty() && url.is_empty() && content.is_empty() {
        return None;
    }

    let evidence = compact_relevant_excerpt(content, terms, 1_200);
    if evidence.is_empty() && content.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !title.is_empty() {
        parts.push(format!("Document: {title}"));
    }
    if !url.is_empty() {
        parts.push(format!("URL: {url}"));
    }
    if !evidence.is_empty() {
        parts.push(format!("Observation: {evidence}"));
    }
    Some(format!("- {}", parts.join(" | ")))
}

fn compact_relevant_excerpt(text: &str, terms: &[String], max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let normalized = trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if terms.is_empty() {
        return truncate_final_reply_evidence(&normalized, max_chars);
    }

    let sentence_normalized = normalized.replace("; ", ". ");
    let sentences = sentence_normalized
        .split(". ")
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty())
        .collect::<Vec<_>>();
    let mut selected = Vec::new();
    for sentence in sentences {
        let lower = sentence.to_ascii_lowercase();
        if terms.iter().any(|term| lower.contains(term)) || contains_numeric_signal(sentence) {
            selected.push(sentence);
        }
        if selected.join(". ").chars().count() >= max_chars {
            break;
        }
    }
    if selected.is_empty() {
        truncate_final_reply_evidence(&normalized, max_chars)
    } else {
        truncate_final_reply_evidence(&format!("{}.", selected.join(". ")), max_chars)
    }
}

fn contains_numeric_signal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.contains('$')
        || text.contains('%')
        || lower.contains("market cap")
        || lower.contains("trading volume")
        || lower.contains("price")
        || lower.contains("change")
}

pub(super) fn contextual_recent_session_events_context(
    history: &[ChatMessage],
    prefer_browser_semantics: bool,
    resolved_scope: IntentScopeProfile,
    goal: &str,
) -> String {
    let recent_events = build_recent_session_events_context(history, prefer_browser_semantics);
    if prefer_browser_semantics || !matches!(resolved_scope, IntentScopeProfile::WorkspaceOps) {
        return recent_events;
    }

    let evidence = final_reply_evidence_context(history, goal, "");
    if evidence.trim().is_empty() {
        return recent_events;
    }

    format!(
        "Relevant workspace evidence for answering the user's request:\n{}\n\nRecent session events:\n{}",
        evidence.trim(),
        recent_events.trim()
    )
}

fn truncate_final_reply_evidence(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.trim().to_string();
    }
    let kept = max_chars.saturating_sub(3);
    let truncated = text.chars().take(kept).collect::<String>();
    format!("{}...", truncated.trim_end())
}

fn extract_goal_relevant_evidence(content: &str, goal: &str, max_chars: usize) -> String {
    let terms = significant_goal_terms(goal);
    let heading_outline = markdown_heading_outline_for_goal(content, goal, 80);
    if terms.is_empty() {
        let rendered = if heading_outline.is_empty() {
            content.to_string()
        } else {
            format!("{heading_outline}\n\n{content}")
        };
        return truncate_final_reply_evidence(&rendered, max_chars);
    }

    let lines = content.lines().collect::<Vec<_>>();
    let mut selected = std::collections::BTreeSet::<usize>::new();
    for (line_idx, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if terms.iter().any(|term| lower.contains(term)) {
            let start = line_idx.saturating_sub(3);
            let end = (line_idx + 4).min(lines.len());
            for idx in start..end {
                selected.insert(idx);
            }
        }
    }

    if selected.is_empty() {
        let rendered = if heading_outline.is_empty() {
            content.to_string()
        } else {
            format!("{heading_outline}\n\n{content}")
        };
        return truncate_final_reply_evidence(&rendered, max_chars);
    }

    let mut rendered = String::new();
    if !heading_outline.is_empty() {
        rendered.push_str(&heading_outline);
        rendered.push_str("\n...\n");
    }
    let mut previous = None::<usize>;
    for idx in selected {
        if previous.is_some_and(|prev| idx > prev + 1) {
            rendered.push_str("\n...\n");
        }
        previous = Some(idx);
        rendered.push_str(lines[idx]);
        rendered.push('\n');
        if rendered.chars().count() >= max_chars {
            break;
        }
    }
    truncate_final_reply_evidence(rendered.trim(), max_chars)
}

fn markdown_heading_outline_for_goal(content: &str, goal: &str, max_headings: usize) -> String {
    let lower_goal = goal.to_ascii_lowercase();
    if !lower_goal.contains("guide")
        && !lower_goal.contains("plan")
        && !lower_goal.contains("progress")
        && !lower_goal.contains("stage")
    {
        return String::new();
    }

    let headings = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') {
                return None;
            }
            let level = trimmed.chars().take_while(|ch| *ch == '#').count();
            if level == 0
                || level > 4
                || !trimmed.chars().nth(level).is_some_and(char::is_whitespace)
            {
                return None;
            }
            Some(trimmed.to_string())
        })
        .take(max_headings)
        .collect::<Vec<_>>();

    if headings.is_empty() {
        String::new()
    } else {
        format!("Markdown heading outline:\n{}", headings.join("\n"))
    }
}

fn significant_goal_terms(goal: &str) -> Vec<String> {
    let stop_words = [
        "about",
        "agent",
        "are",
        "between",
        "does",
        "explain",
        "from",
        "how",
        "look",
        "mode",
        "per",
        "repo",
        "repository",
        "studio",
        "this",
        "what",
        "where",
    ];
    goal.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| term.len() >= 4)
        .filter(|term| !stop_words.iter().any(|stop| term == stop))
        .take(12)
        .collect()
}
