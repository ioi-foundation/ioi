use super::*;

pub(crate) fn synthesis_query_contract(pending: &PendingSearchCompletion) -> String {
    let contract = pending.query_contract.trim();
    if !contract.is_empty() {
        return contract.to_string();
    }
    pending.query.trim().to_string()
}

pub(crate) fn fallback_search_summary(query: &str, url: &str) -> String {
    format!(
        "Searched '{}' at {}, but structured extraction failed. Retry refinement if needed.",
        query, url
    )
}

pub(crate) fn strip_markup(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if in_tag => {}
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn extract_urls(input: &str, limit: usize) -> Vec<String> {
    let mut urls = Vec::new();
    for raw in input.split_whitespace() {
        let trimmed = raw
            .trim_matches(|ch: char| ",.;:!?)]}\"'".contains(ch))
            .trim();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            continue;
        }
        if urls.iter().any(|existing| existing == trimmed) {
            continue;
        }
        urls.push(trimmed.to_string());
        if urls.len() >= limit {
            break;
        }
    }
    urls
}

pub(crate) fn extract_finding_lines(input: &str, limit: usize) -> Vec<String> {
    let mut findings = Vec::new();
    for line in input.lines() {
        let normalized = compact_whitespace(line).trim().to_string();
        if normalized.len() < 24 || normalized.len() > 200 {
            continue;
        }
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            continue;
        }
        if normalized.to_ascii_lowercase().contains("cookie")
            || normalized.to_ascii_lowercase().contains("javascript")
        {
            continue;
        }
        if findings.iter().any(|existing| existing == &normalized) {
            continue;
        }
        findings.push(normalized);
        if findings.len() >= limit {
            break;
        }
    }
    findings
}

pub(crate) fn summarize_search_results(query: &str, url: &str, extract_text: &str) -> String {
    let capped = extract_text
        .chars()
        .take(MAX_SEARCH_EXTRACT_CHARS)
        .collect::<String>();
    let stripped = strip_markup(&capped);
    let findings = extract_finding_lines(&stripped, 3);
    let urls = extract_urls(&capped, 2);

    let mut bullets: Vec<String> = Vec::new();
    for finding in findings {
        bullets.push(finding);
        if bullets.len() >= 3 {
            break;
        }
    }
    for link in urls.iter() {
        if bullets.len() >= 3 {
            break;
        }
        bullets.push(format!("Top link: {}", link));
    }

    if bullets.is_empty() {
        let snippet = compact_whitespace(&stripped)
            .chars()
            .take(180)
            .collect::<String>();
        if snippet.is_empty() {
            bullets.push("No high-signal snippets were extracted.".to_string());
        } else {
            bullets.push(format!("Extracted snippet: {}", snippet));
        }
    }

    let refinement_hint = if let Some(link) = urls.first() {
        format!(
            "Open '{}' or refine with more specific keywords (site:, date range, exact phrase).",
            link
        )
    } else {
        "Refine with more specific keywords (site:, date range, exact phrase).".to_string()
    };

    let mut summary = format!("Search summary for '{}':\n", query);
    for bullet in bullets.into_iter().take(3) {
        summary.push_str(&format!("- {}\n", bullet));
    }
    summary.push_str(&format!("- Source URL: {}\n", url));
    summary.push_str(&format!("Next refinement: {}", refinement_hint));
    summary
}

pub(crate) fn web_pipeline_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn web_pipeline_remaining_budget_ms(deadline_ms: u64, now_ms: u64) -> u64 {
    if deadline_ms == 0 {
        return u64::MAX;
    }
    deadline_ms.saturating_sub(now_ms)
}

pub(crate) fn web_pipeline_can_queue_initial_read(deadline_ms: u64, now_ms: u64) -> bool {
    if deadline_ms == 0 {
        return true;
    }
    web_pipeline_remaining_budget_ms(deadline_ms, now_ms)
        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ
}

pub(crate) fn web_pipeline_can_queue_probe_search(deadline_ms: u64, now_ms: u64) -> bool {
    if deadline_ms == 0 {
        return true;
    }
    web_pipeline_remaining_budget_ms(deadline_ms, now_ms)
        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
}

pub(crate) fn web_pipeline_observed_attempt_count(pending: &PendingSearchCompletion) -> u64 {
    pending
        .attempted_urls
        .len()
        .max(pending.successful_reads.len() + pending.blocked_urls.len())
        .max(1) as u64
}

pub(crate) fn web_pipeline_observed_attempt_latency_ms(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> u64 {
    if pending.started_at_ms == 0 || now_ms <= pending.started_at_ms {
        return 0;
    }
    let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
    elapsed_ms / web_pipeline_observed_attempt_count(pending)
}

pub(crate) fn web_pipeline_constraint_guard_ms(
    pending: &PendingSearchCompletion,
    read_guard_ms: u64,
    non_constraint_guard_ms: u64,
) -> u64 {
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    if projection.has_constraint_objective() {
        read_guard_ms
    } else {
        non_constraint_guard_ms
    }
}

pub(crate) fn web_pipeline_required_read_budget_ms(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> u64 {
    if pending.deadline_ms == 0 {
        return 0;
    }
    let observed_latency = web_pipeline_observed_attempt_latency_ms(pending, now_ms);
    let constraint_guard = web_pipeline_constraint_guard_ms(
        pending,
        WEB_PIPELINE_LATENCY_READ_GUARD_MS,
        WEB_PIPELINE_LATENCY_READ_GUARD_MS / 2,
    );
    WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ
        .max(observed_latency.saturating_add(constraint_guard))
}

pub(crate) fn web_pipeline_required_probe_budget_ms(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> u64 {
    if pending.deadline_ms == 0 {
        return 0;
    }
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let observed_latency = web_pipeline_observed_attempt_latency_ms(pending, now_ms);
    let strict_grounding_guard = if projection.strict_grounded_compatibility() {
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS / 2
    } else {
        0
    };
    let constraint_guard = web_pipeline_constraint_guard_ms(
        pending,
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS,
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS / 2,
    );
    WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE.max(
        observed_latency
            .saturating_add(constraint_guard)
            .saturating_add(strict_grounding_guard),
    )
}

pub(crate) fn web_pipeline_can_queue_initial_read_latency_aware(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    remaining >= web_pipeline_required_read_budget_ms(pending, now_ms)
}

pub(crate) fn web_pipeline_can_queue_probe_search_latency_aware(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    remaining >= web_pipeline_required_probe_budget_ms(pending, now_ms)
}

pub(crate) fn web_pipeline_latency_pressure(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> WebPipelineLatencyPressure {
    if pending.deadline_ms == 0 {
        return WebPipelineLatencyPressure::Nominal;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    let required_read_budget = web_pipeline_required_read_budget_ms(pending, now_ms);
    if remaining < required_read_budget {
        return WebPipelineLatencyPressure::Critical;
    }
    if remaining < required_read_budget.saturating_add(WEB_PIPELINE_LATENCY_ELEVATED_BUFFER_MS) {
        return WebPipelineLatencyPressure::Elevated;
    }
    WebPipelineLatencyPressure::Nominal
}

pub(crate) fn web_pipeline_latency_pressure_label(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> &'static str {
    match web_pipeline_latency_pressure(pending, now_ms) {
        WebPipelineLatencyPressure::Nominal => "nominal",
        WebPipelineLatencyPressure::Elevated => "elevated",
        WebPipelineLatencyPressure::Critical => "critical",
    }
}

pub(crate) fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    // Howard Hinnant civil-from-days algorithm, converted to Rust.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

pub(crate) fn iso_date_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

pub(crate) fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

pub(crate) fn normalize_confidence_label(label: &str) -> String {
    let normalized = label.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "high" | "medium" | "low" => normalized,
        _ => "low".to_string(),
    }
}

pub(crate) fn parse_web_evidence_bundle(raw: &str) -> Option<WebEvidenceBundle> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str::<WebEvidenceBundle>(trimmed).ok()
}

pub(crate) fn candidate_source_hints_from_bundle_ranked(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sources = bundle.sources.clone();
    sources.sort_by(|left, right| {
        let left_title = left.title.as_deref().unwrap_or_default();
        let right_title = right.title.as_deref().unwrap_or_default();
        let left_excerpt = left.snippet.as_deref().unwrap_or_default();
        let right_excerpt = right.snippet.as_deref().unwrap_or_default();
        let left_signals = analyze_source_record_signals(&left.url, left_title, left_excerpt);
        let right_signals = analyze_source_record_signals(&right.url, right_title, right_excerpt);

        let left_key = (
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(false),
            left_signals.provenance_hits,
            left_signals.primary_event_hits,
        );
        let right_key = (
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(false),
            right_signals.provenance_hits,
            right_signals.primary_event_hits,
        );

        right_key
            .cmp(&left_key)
            .then_with(|| {
                left.rank
                    .unwrap_or(u32::MAX)
                    .cmp(&right.rank.unwrap_or(u32::MAX))
            })
            .then_with(|| left.url.cmp(&right.url))
    });
    for source in sources {
        let url = source.url.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: url.to_string(),
            title: source
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(source.snippet.as_deref().unwrap_or_default(), 180),
        });
    }
    hints
}

pub(crate) fn document_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    for doc in &bundle.documents {
        let url = doc.url.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: url.to_string(),
            title: doc
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS),
        });
    }
    hints
}

pub(crate) fn candidate_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    candidate_source_hints_from_bundle_ranked(bundle)
}

pub(crate) fn candidate_urls_from_bundle(bundle: &WebEvidenceBundle) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();

    for hint in candidate_source_hints_from_bundle_ranked(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    for hint in document_source_hints_from_bundle(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    urls
}

pub(crate) fn constrained_candidate_inventory_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> (Vec<String>, Vec<PendingSearchReadSummary>) {
    let mut candidate_hints = candidate_source_hints_from_bundle_ranked(bundle);
    let mut seen_urls = candidate_hints
        .iter()
        .map(|hint| hint.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    for hint in document_source_hints_from_bundle(bundle) {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() || !seen_urls.insert(trimmed.to_string()) {
            continue;
        }
        candidate_hints.push(hint);
    }

    if candidate_hints.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_hints,
        locality_hint,
    );
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let min_required = min_sources.max(1) as usize;

    let mut ranked = candidate_hints
        .into_iter()
        .enumerate()
        .map(|(idx, hint)| {
            let title = hint.title.as_deref().unwrap_or_default();
            let envelope_score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                &hint.url,
                title,
                &hint.excerpt,
            );
            let resolves_constraint =
                envelope_score_resolves_constraint(constraints, &envelope_score);
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                &hint.url,
                title,
                &hint.excerpt,
            );
            let source_signals = analyze_source_record_signals(&hint.url, title, &hint.excerpt);
            let time_sensitive_resolvable_payload =
                candidate_time_sensitive_resolvable_payload(title, &hint.excerpt);
            RankedAcquisitionCandidate {
                idx,
                hint,
                envelope_score,
                resolves_constraint,
                time_sensitive_resolvable_payload,
                compatibility,
                source_relevance_score: source_signals.relevance_score(false),
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
        let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
        right
            .time_sensitive_resolvable_payload
            .cmp(&left.time_sensitive_resolvable_payload)
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.resolves_constraint.cmp(&left.resolves_constraint))
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| {
                compare_candidate_evidence_scores_desc(&left.envelope_score, &right.envelope_score)
            })
            .then_with(|| {
                right
                    .source_relevance_score
                    .cmp(&left.source_relevance_score)
            })
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.hint.url.cmp(&right.hint.url))
    });

    let has_constraint_objective = projection.has_constraint_objective();
    let compatible_candidates = ranked
        .iter()
        .filter(|candidate| compatibility_passes_projection(&projection, &candidate.compatibility))
        .count();
    let should_filter_by_compatibility =
        has_constraint_objective && compatible_candidates >= min_required;

    let mut filtered = ranked.iter().collect::<Vec<_>>();
    if should_filter_by_compatibility {
        filtered.retain(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
        });
    }

    let resolvable_candidates = filtered
        .iter()
        .filter(|candidate| candidate.resolves_constraint)
        .count();
    if has_constraint_objective && resolvable_candidates >= min_required {
        filtered.retain(|candidate| candidate.resolves_constraint);
    }

    let selected = if filtered.is_empty() {
        if projection.strict_grounded_compatibility() {
            Vec::new()
        } else {
            ranked.iter().collect::<Vec<_>>()
        }
    } else {
        filtered
    };
    let mut selected_urls = Vec::new();
    let mut selected_hints = Vec::new();
    let mut selected_seen = BTreeSet::new();
    for candidate in selected {
        let url = candidate.hint.url.trim();
        if url.is_empty() || !selected_seen.insert(url.to_string()) {
            continue;
        }
        selected_urls.push(url.to_string());
        selected_hints.push(candidate.hint.clone());
    }

    (selected_urls, selected_hints)
}

pub(crate) fn next_pending_web_candidate(pending: &PendingSearchCompletion) -> Option<String> {
    let mut attempted = BTreeSet::new();
    for url in &pending.attempted_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }
    for url in &pending.blocked_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let prefer_host_diversity = prefers_single_fact_snapshot(&query_contract);
    if prefer_host_diversity {
        let projection =
            build_query_constraint_projection(&query_contract, 1, &pending.candidate_source_hints);
        let envelope_constraints = &projection.constraints;
        let grounded_anchor_constrained = projection.strict_grounded_compatibility();
        let envelope_policy = ResolutionPolicy::default();
        let mut ranked_candidates = pending
            .candidate_urls
            .iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                let trimmed = candidate.trim();
                if trimmed.is_empty() || attempted.contains(trimmed) {
                    return None;
                }
                let hint = hint_for_url(pending, trimmed);
                let title = hint
                    .and_then(|entry| entry.title.as_deref())
                    .unwrap_or_default();
                let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
                let envelope_score = single_snapshot_candidate_envelope_score(
                    envelope_constraints,
                    envelope_policy,
                    trimmed,
                    title,
                    excerpt,
                );
                let compatibility = candidate_constraint_compatibility(
                    envelope_constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    title,
                    excerpt,
                );
                let resolvable_payload =
                    candidate_time_sensitive_resolvable_payload(title, excerpt);
                let source_relevance_score =
                    analyze_source_record_signals(trimmed, title, excerpt).relevance_score(false);
                Some((
                    idx,
                    trimmed.to_string(),
                    envelope_score,
                    compatibility,
                    resolvable_payload,
                    source_relevance_score,
                ))
            })
            .collect::<Vec<_>>();
        ranked_candidates.sort_by(|left, right| {
            right
                .4
                .cmp(&left.4)
                .then_with(|| {
                    let right_passes = compatibility_passes_projection(&projection, &right.3);
                    let left_passes = compatibility_passes_projection(&projection, &left.3);
                    right_passes.cmp(&left_passes)
                })
                .then_with(|| right.3.compatibility_score.cmp(&left.3.compatibility_score))
                .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
                .then_with(|| right.5.cmp(&left.5))
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        let has_compatible_candidates =
            ranked_candidates
                .iter()
                .any(|(_, _, _, compatibility, _, _)| {
                    compatibility_passes_projection(&projection, compatibility)
                });
        let requires_semantic_locality_alignment = projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && projection.locality_scope.is_some()
            && projection
                .query_native_tokens
                .iter()
                .any(|token| !projection.locality_tokens.contains(token));
        let exploratory_attempts_without_compatibility = pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty() && !is_search_hub_url(url))
            .collect::<BTreeSet<_>>()
            .len();
        let exploratory_read_cap = SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY
            .saturating_add(
                single_snapshot_additional_probe_attempt_count(pending)
                    .min(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES),
            );
        let can_issue_exploratory_read =
            exploratory_attempts_without_compatibility < exploratory_read_cap;
        if requires_semantic_locality_alignment
            && !has_compatible_candidates
            && !can_issue_exploratory_read
        {
            return None;
        }

        let mut attempted_hosts = BTreeSet::new();
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                continue;
            }
            if let Some(host) = source_host(trimmed) {
                attempted_hosts.insert(host);
            }
        }

        for (_, candidate, _, compatibility, _, _) in &ranked_candidates {
            if has_compatible_candidates
                && !compatibility_passes_projection(&projection, compatibility)
            {
                continue;
            }
            if let Some(host) = source_host(candidate) {
                if attempted_hosts.contains(&host) {
                    continue;
                }
            }
            return Some(candidate.clone());
        }

        if has_compatible_candidates {
            if let Some((_, candidate, _, _, _, _)) =
                ranked_candidates
                    .iter()
                    .find(|(_, _, _, compatibility, _, _)| {
                        compatibility_passes_projection(&projection, compatibility)
                    })
            {
                return Some(candidate.clone());
            }
        }

        if grounded_anchor_constrained {
            if !has_compatible_candidates && can_issue_exploratory_read {
                if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
                    return Some(candidate.clone());
                }
            }
            return None;
        }

        if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
            return Some(candidate.clone());
        }
    }

    for candidate in &pending.candidate_urls {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if attempted.contains(trimmed) {
            continue;
        }
        return Some(trimmed.to_string());
    }

    None
}

pub(crate) fn mark_pending_web_attempted(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .attempted_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.attempted_urls.push(trimmed.to_string());
}

pub(crate) fn mark_pending_web_blocked(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .blocked_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.blocked_urls.push(trimmed.to_string());
}

pub(crate) fn normalize_optional_title(value: Option<String>) -> Option<String> {
    value.and_then(|title| {
        let trimmed = title.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub(crate) fn prefer_title(existing: Option<String>, incoming: Option<String>) -> Option<String> {
    let existing = normalize_optional_title(existing);
    let incoming = normalize_optional_title(incoming);
    match (existing, incoming) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            let left_low = is_low_signal_title(&left);
            let right_low = is_low_signal_title(&right);
            if left_low != right_low {
                return if right_low { Some(left) } else { Some(right) };
            }
            if right.chars().count() > left.chars().count() {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

pub(crate) fn prefer_excerpt(existing: String, incoming: String) -> String {
    let left = existing.trim().to_string();
    let right = incoming.trim().to_string();
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let left_current = contains_current_condition_metric_signal(&left);
    let right_current = contains_current_condition_metric_signal(&right);
    if right_current != left_current {
        return if right_current { right } else { left };
    }

    let left_metric = contains_metric_signal(&left);
    let right_metric = contains_metric_signal(&right);
    if right_metric != left_metric {
        return if right_metric { right } else { left };
    }

    let left_low = is_low_signal_excerpt(&left);
    let right_low = is_low_signal_excerpt(&right);
    if right_low != left_low {
        return if right_low { left } else { right };
    }

    if right.chars().count() > left.chars().count() {
        right
    } else {
        left
    }
}

pub(crate) fn merge_pending_source_record(
    existing: PendingSearchReadSummary,
    incoming: PendingSearchReadSummary,
) -> PendingSearchReadSummary {
    let url = if existing.url.trim().is_empty() {
        incoming.url.trim().to_string()
    } else {
        existing.url.trim().to_string()
    };
    PendingSearchReadSummary {
        url,
        title: prefer_title(existing.title, incoming.title),
        excerpt: prefer_excerpt(existing.excerpt, incoming.excerpt),
    }
}

pub(crate) fn merge_url_sequence(existing: Vec<String>, incoming: Vec<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();
    for url in existing.into_iter().chain(incoming.into_iter()) {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(trimmed.to_string());
    }
    merged
}

pub(crate) fn merge_pending_search_completion(
    existing: PendingSearchCompletion,
    incoming: PendingSearchCompletion,
) -> PendingSearchCompletion {
    let existing_contract = existing.query_contract.trim();
    let incoming_contract = incoming.query_contract.trim();
    if !existing_contract.is_empty()
        && !incoming_contract.is_empty()
        && !existing_contract.eq_ignore_ascii_case(incoming_contract)
    {
        return incoming;
    }

    let existing_query = existing.query.trim();
    let incoming_query = incoming.query.trim();
    if existing_contract.is_empty()
        && incoming_contract.is_empty()
        && !existing_query.is_empty()
        && !incoming_query.is_empty()
        && !existing_query.eq_ignore_ascii_case(incoming_query)
    {
        return incoming;
    }

    let successful_reads = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .successful_reads
            .into_iter()
            .chain(incoming.successful_reads.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }
        merged_by_url.into_values().collect::<Vec<_>>()
    };

    let attempted_urls = merge_url_sequence(existing.attempted_urls, incoming.attempted_urls);
    let blocked_urls = merge_url_sequence(existing.blocked_urls, incoming.blocked_urls);

    let mut attempted_or_resolved = BTreeSet::new();
    for url in attempted_urls.iter().chain(blocked_urls.iter()) {
        attempted_or_resolved.insert(url.trim().to_string());
    }
    for source in &successful_reads {
        let trimmed = source.url.trim();
        if !trimmed.is_empty() {
            attempted_or_resolved.insert(trimmed.to_string());
        }
    }

    let candidate_urls = merge_url_sequence(existing.candidate_urls, incoming.candidate_urls)
        .into_iter()
        .filter(|url| !attempted_or_resolved.contains(url))
        .collect::<Vec<_>>();

    let candidate_source_hints = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .candidate_source_hints
            .into_iter()
            .chain(incoming.candidate_source_hints.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }

        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for url in &candidate_urls {
            if let Some(source) = merged_by_url.get(url) {
                ordered.push(source.clone());
                seen.insert(url.clone());
            }
        }
        for (url, source) in merged_by_url {
            if seen.insert(url) {
                ordered.push(source);
            }
        }
        ordered
    };

    PendingSearchCompletion {
        query: if incoming_query.is_empty() {
            existing.query
        } else if existing_query.is_empty() || !existing_query.eq_ignore_ascii_case(incoming_query)
        {
            incoming.query
        } else {
            existing.query
        },
        query_contract: if existing_contract.is_empty() {
            incoming.query_contract
        } else {
            existing.query_contract
        },
        url: if existing.url.trim().is_empty() {
            incoming.url
        } else {
            existing.url
        },
        started_step: if existing.started_at_ms > 0 || existing.started_step > 0 {
            existing.started_step
        } else {
            incoming.started_step
        },
        started_at_ms: if existing.started_at_ms > 0 {
            existing.started_at_ms
        } else {
            incoming.started_at_ms
        },
        deadline_ms: if existing.deadline_ms > 0 {
            existing.deadline_ms
        } else {
            incoming.deadline_ms
        },
        candidate_urls,
        candidate_source_hints,
        attempted_urls,
        blocked_urls,
        successful_reads,
        min_sources: existing.min_sources.max(incoming.min_sources),
    }
}

pub(crate) fn compact_excerpt(input: &str, max_chars: usize) -> String {
    compact_whitespace(input)
        .chars()
        .take(max_chars)
        .collect::<String>()
}

pub(crate) fn prioritized_signal_excerpt(input: &str, max_chars: usize) -> String {
    let compact = compact_whitespace(input);
    if compact.is_empty() {
        return String::new();
    }

    if let Some(metric) = first_metric_sentence(&compact) {
        return metric.chars().take(max_chars).collect();
    }

    if let Some(actionable) = actionable_excerpt(&compact) {
        return actionable.chars().take(max_chars).collect();
    }

    if is_low_signal_excerpt(&compact) {
        return String::new();
    }

    compact.chars().take(max_chars).collect()
}

pub(crate) fn source_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed
        .host_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(host.to_ascii_lowercase())
}

pub(crate) fn source_evidence_signals(source: &PendingSearchReadSummary) -> SourceSignalProfile {
    let title = source.title.as_deref().unwrap_or_default();
    analyze_source_record_signals(&source.url, title, &source.excerpt)
}

pub(crate) fn has_primary_status_authority(signals: SourceSignalProfile) -> bool {
    signals.official_status_host_hits > 0 || signals.primary_status_surface_hits > 0
}

pub(crate) fn is_low_priority_coverage_story(source: &PendingSearchReadSummary) -> bool {
    source_evidence_signals(source).low_priority_dominates()
}

pub(crate) fn is_low_signal_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "google news" | "news" | "home" | "homepage" | "untitled"
    ) || lower.starts_with("google news -")
}

pub(crate) fn actionable_source_signal_strength(signals: SourceSignalProfile) -> usize {
    effective_primary_event_hits(signals) + signals.impact_hits + signals.mitigation_hits
}

pub(crate) fn low_priority_source_signal_strength(signals: SourceSignalProfile) -> usize {
    signals.low_priority_hits + signals.secondary_coverage_hits + signals.documentation_surface_hits
}

pub(crate) fn effective_primary_event_hits(signals: SourceSignalProfile) -> usize {
    let surface_bias = signals
        .provenance_hits
        .max(signals.primary_status_surface_hits);
    signals
        .primary_event_hits
        .saturating_sub(surface_bias.min(signals.primary_event_hits))
}

pub(crate) fn excerpt_has_claim_signal(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return false;
    }
    let metric_schema = analyze_metric_schema(trimmed);
    if metric_schema.has_metric_payload() || metric_schema.has_current_observation_payload() {
        return true;
    }
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_timeline_claim = signals.timeline_hits > 0
        && (metric_schema.timestamp_hits > 0
            || (metric_schema.observation_hits > 0
                && trimmed.chars().any(|ch| ch.is_ascii_digit())));
    effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0
        || has_timeline_claim
}

pub(crate) fn excerpt_actionability_score(excerpt: &str) -> usize {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let metric_schema = analyze_metric_schema(trimmed);
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_claim_signal = excerpt_has_claim_signal(trimmed);
    let digit_hits = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .count()
        .min(6);
    let actionability_signal = actionable_source_signal_strength(signals).min(8);
    let low_priority_signal = low_priority_source_signal_strength(signals).min(8);

    let mut score = 0usize;
    if metric_schema.has_current_observation_payload() {
        score = score.saturating_add(6);
    }
    if metric_schema.has_metric_payload() {
        score = score.saturating_add(4);
    }
    score = score
        .saturating_add(metric_schema.axis_hits.len().min(4).saturating_mul(2))
        .saturating_add(metric_schema.numeric_token_hits.min(4))
        .saturating_add(metric_schema.unit_hits.min(4))
        .saturating_add(metric_schema.observation_hits.min(3))
        .saturating_add(metric_schema.timestamp_hits.min(3));
    if has_claim_signal {
        let provenance_context = signals
            .provenance_hits
            .saturating_add(signals.primary_status_surface_hits)
            .saturating_add(signals.official_status_host_hits)
            .min(4);
        score = score
            .saturating_add(ACTIONABLE_EXCERPT_CLAIM_BASE_BONUS)
            .saturating_add(actionability_signal)
            .saturating_add(provenance_context);
    }
    score = score.saturating_add(digit_hits);
    score.saturating_sub(low_priority_signal)
}

pub(crate) fn is_low_signal_excerpt(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
        return true;
    }
    let has_numeric_hint = trimmed.chars().any(|ch| ch.is_ascii_digit());
    if !excerpt_has_claim_signal(trimmed) && !has_numeric_hint {
        return true;
    }

    let actionability_score = excerpt_actionability_score(trimmed);
    if actionability_score >= ACTIONABLE_EXCERPT_MIN_SCORE {
        return false;
    }

    let anchor_token_count = normalized_anchor_tokens(trimmed).len();
    if !has_numeric_hint {
        return true;
    }
    anchor_token_count < 3
}

pub(crate) fn actionable_excerpt(excerpt: &str) -> Option<String> {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let compact = compact_whitespace(trimmed);
    if compact.is_empty() {
        return None;
    }

    let mut best_segment: Option<(usize, String)> = None;
    for segment in compact
        .split(['.', '!', '?', ';'])
        .map(compact_whitespace)
        .filter(|value| !value.is_empty())
    {
        if segment.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
            continue;
        }
        if !excerpt_has_claim_signal(&segment) {
            continue;
        }
        let score = excerpt_actionability_score(&segment);
        if score < ACTIONABLE_EXCERPT_MIN_SCORE {
            continue;
        }
        let replace = best_segment
            .as_ref()
            .map(|(best_score, best_text)| {
                score > *best_score || (score == *best_score && segment.len() < best_text.len())
            })
            .unwrap_or(true);
        if replace {
            best_segment = Some((score, segment));
        }
    }

    if let Some((_, selected)) = best_segment {
        return Some(
            selected
                .chars()
                .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
                .collect(),
        );
    }

    if excerpt_actionability_score(&compact) < ACTIONABLE_EXCERPT_MIN_SCORE
        || is_low_signal_excerpt(&compact)
    {
        return None;
    }

    Some(
        compact
            .chars()
            .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UrlStructuralKey {
    host: String,
    path: String,
    query_tokens: BTreeSet<String>,
}

pub(crate) fn normalized_url_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let lowered = trimmed.to_ascii_lowercase();
    let stripped = lowered.trim_end_matches('/');
    if stripped.is_empty() {
        "/".to_string()
    } else {
        stripped.to_string()
    }
}

pub(crate) fn url_structural_key(url: &str) -> Option<UrlStructuralKey> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let path = normalized_url_path(parsed.path());
    let mut query_tokens = BTreeSet::new();
    if let Some(query) = parsed.query() {
        query_tokens.extend(normalized_locality_tokens(query));
        query_tokens.extend(normalized_anchor_tokens(query));
    }

    Some(UrlStructuralKey {
        host,
        path,
        query_tokens,
    })
}

pub(crate) fn normalized_url_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(key) = url_structural_key(trimmed) {
        let mut normalized = format!("{}{}", key.host, key.path);
        if !key.query_tokens.is_empty() {
            normalized.push('?');
            normalized.push_str(
                &key.query_tokens
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        return normalized;
    }
    trimmed
        .trim_end_matches('/')
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase()
}

pub(crate) fn url_structural_query_overlap(
    left: &UrlStructuralKey,
    right: &UrlStructuralKey,
) -> usize {
    left.query_tokens.intersection(&right.query_tokens).count()
}

pub(crate) fn url_structurally_equivalent(left: &str, right: &str) -> bool {
    let left_trimmed = left.trim();
    let right_trimmed = right.trim();
    if left_trimmed.is_empty() || right_trimmed.is_empty() {
        return false;
    }
    if left_trimmed.eq_ignore_ascii_case(right_trimmed) {
        return true;
    }

    match (
        url_structural_key(left_trimmed),
        url_structural_key(right_trimmed),
    ) {
        (Some(left_key), Some(right_key)) => {
            if left_key.host != right_key.host || left_key.path != right_key.path {
                return false;
            }
            if left_key.query_tokens.is_empty() || right_key.query_tokens.is_empty() {
                return true;
            }
            url_structural_query_overlap(&left_key, &right_key) > 0
        }
        _ => normalized_url_literal(left_trimmed) == normalized_url_literal(right_trimmed),
    }
}

pub(crate) fn hint_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(exact) = pending
        .candidate_source_hints
        .iter()
        .find(|hint| hint.url.trim().eq_ignore_ascii_case(trimmed))
    {
        return Some(exact);
    }

    let target_key = url_structural_key(trimmed)?;
    let mut best_hint: Option<&PendingSearchReadSummary> = None;
    let mut best_overlap = 0usize;
    for hint in &pending.candidate_source_hints {
        let hint_trimmed = hint.url.trim();
        if hint_trimmed.is_empty() {
            continue;
        }
        let Some(hint_key) = url_structural_key(hint_trimmed) else {
            continue;
        };
        if hint_key.host != target_key.host || hint_key.path != target_key.path {
            continue;
        }
        if !hint_key.query_tokens.is_empty()
            && !target_key.query_tokens.is_empty()
            && url_structural_query_overlap(&hint_key, &target_key) == 0
        {
            continue;
        }
        let overlap = url_structural_query_overlap(&hint_key, &target_key);
        let should_replace = best_hint.is_none() || overlap > best_overlap;
        if should_replace {
            best_overlap = overlap;
            best_hint = Some(hint);
        }
    }

    best_hint
}

pub(crate) fn push_pending_web_success(
    pending: &mut PendingSearchCompletion,
    url: &str,
    title: Option<String>,
    excerpt: String,
) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .successful_reads
        .iter()
        .any(|existing| url_structurally_equivalent(existing.url.trim(), trimmed))
    {
        return;
    }

    let hint = hint_for_url(pending, trimmed);
    let mut resolved_title = title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    if resolved_title
        .as_deref()
        .map(is_low_signal_title)
        .unwrap_or(true)
    {
        if let Some(hint_title) = hint
            .and_then(|value| value.title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            resolved_title = Some(hint_title.to_string());
        }
    }

    let mut resolved_excerpt = excerpt.trim().to_string();
    if let Some(hint_excerpt) = hint
        .map(|value| value.excerpt.trim())
        .filter(|value| !value.is_empty())
    {
        let resolved_has_current = contains_current_condition_metric_signal(&resolved_excerpt);
        let hint_has_current = contains_current_condition_metric_signal(hint_excerpt);
        let resolved_has_metric = contains_metric_signal(&resolved_excerpt);
        let hint_has_metric = contains_metric_signal(hint_excerpt);
        let should_use_hint = is_low_signal_excerpt(&resolved_excerpt)
            || (hint_has_current && !resolved_has_current)
            || (!resolved_has_metric && hint_has_metric);
        if should_use_hint {
            resolved_excerpt = hint_excerpt.to_string();
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let min_sources_required = pending.min_sources.max(1) as usize;
    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    if reject_search_hub && is_search_hub_url(trimmed) {
        return;
    }
    if projection.query_facets.grounded_external_required || time_sensitive {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        );
        let mut compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
        if !compatibility_passes {
            if let Some(hint_entry) = hint {
                let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                let hint_excerpt = hint_entry.excerpt.trim();
                let hint_compatibility = candidate_constraint_compatibility(
                    &projection.constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    hint_title,
                    hint_excerpt,
                );
                if compatibility_passes_projection(&projection, &hint_compatibility) {
                    compatibility_passes = true;
                    if resolved_title
                        .as_deref()
                        .map(is_low_signal_title)
                        .unwrap_or(true)
                        && !hint_title.is_empty()
                    {
                        resolved_title = Some(hint_title.to_string());
                    }
                    if !hint_excerpt.is_empty() {
                        resolved_excerpt = hint_excerpt.to_string();
                    }
                }
            }
        }
        if !compatibility_passes {
            let has_compatible_alternative =
                pending.candidate_source_hints.iter().any(|candidate| {
                    let candidate_url = candidate.url.trim();
                    if candidate_url.is_empty() || candidate_url.eq_ignore_ascii_case(trimmed) {
                        return false;
                    }
                    if is_search_hub_url(candidate_url) {
                        return false;
                    }
                    let candidate_title = candidate.title.as_deref().unwrap_or_default();
                    let candidate_excerpt = candidate.excerpt.as_str();
                    let candidate_compatibility = candidate_constraint_compatibility(
                        &projection.constraints,
                        &projection.query_facets,
                        &projection.query_native_tokens,
                        &projection.query_tokens,
                        &projection.locality_tokens,
                        projection.locality_scope.is_some(),
                        candidate_url,
                        candidate_title,
                        candidate_excerpt,
                    );
                    compatibility_passes_projection(&projection, &candidate_compatibility)
                });
            let allow_exploratory_first_capture =
                projection.locality_scope_inferred && !projection.locality_tokens.is_empty();
            let allow_exploratory_floor_capture = source_floor_unmet
                && time_sensitive
                && compatibility.locality_compatible
                && !is_search_hub_url(trimmed);
            if (!source_floor_unmet && has_compatible_alternative)
                || (!source_floor_unmet && !pending.successful_reads.is_empty())
                || (!allow_exploratory_first_capture && !allow_exploratory_floor_capture)
            {
                return;
            }
        }

        if time_sensitive {
            let mut resolved_payload = candidate_time_sensitive_resolvable_payload(
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            );
            if !resolved_payload {
                if let Some(hint_entry) = hint {
                    let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                    let hint_excerpt = hint_entry.excerpt.trim();
                    if !hint_excerpt.is_empty()
                        && candidate_time_sensitive_resolvable_payload(hint_title, hint_excerpt)
                    {
                        let hint_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        );
                        if compatibility_passes_projection(&projection, &hint_compatibility) {
                            if !hint_title.is_empty() {
                                resolved_title = Some(hint_title.to_string());
                            }
                            resolved_excerpt = hint_excerpt.to_string();
                            resolved_payload = true;
                        }
                    }
                }
            }
            if !resolved_payload {
                let has_resolvable_alternative = pending
                    .candidate_source_hints
                    .iter()
                    .chain(pending.successful_reads.iter())
                    .any(|candidate| {
                        let candidate_url = candidate.url.trim();
                        if candidate_url.is_empty() || is_search_hub_url(candidate_url) {
                            return false;
                        }
                        if candidate_url.eq_ignore_ascii_case(trimmed) {
                            return false;
                        }
                        let candidate_title = candidate.title.as_deref().unwrap_or_default().trim();
                        let candidate_excerpt = candidate.excerpt.trim();
                        if !candidate_time_sensitive_resolvable_payload(
                            candidate_title,
                            candidate_excerpt,
                        ) {
                            return false;
                        }
                        let candidate_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            candidate_url,
                            candidate_title,
                            candidate_excerpt,
                        );
                        compatibility_passes_projection(&projection, &candidate_compatibility)
                    });
                if has_resolvable_alternative {
                    if source_floor_unmet {
                        // Floor-recovery mode: retain additional locality-compatible reads even
                        // when stronger resolvable alternatives already exist.
                    } else {
                        return;
                    }
                }
            }
        }
    }

    pending.successful_reads.push(PendingSearchReadSummary {
        url: trimmed.to_string(),
        title: resolved_title,
        excerpt: resolved_excerpt,
    });
}

pub(crate) fn append_pending_web_success_fallback(
    pending: &mut PendingSearchCompletion,
    url: &str,
    raw_output: Option<&str>,
) {
    let excerpt =
        prioritized_signal_excerpt(raw_output.unwrap_or_default(), WEB_PIPELINE_EXCERPT_CHARS);
    push_pending_web_success(pending, url, None, excerpt);
}

pub(crate) fn append_pending_web_success_from_bundle(
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    fallback_url: &str,
) {
    if let Some(doc) = bundle.documents.first() {
        let title = doc
            .title
            .clone()
            .or_else(|| {
                bundle
                    .sources
                    .iter()
                    .find(|source| source.source_id == doc.source_id)
                    .and_then(|source| source.title.clone())
            })
            .filter(|value| !value.trim().is_empty());
        let excerpt = prioritized_signal_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &doc.url, title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty() && !url_structurally_equivalent(&doc.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, title, excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    if let Some(source) = bundle.sources.first() {
        let excerpt =
            prioritized_signal_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &source.url, source.title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty()
            && !url_structurally_equivalent(&source.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, source.title.clone(), excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    append_pending_web_success_fallback(pending, fallback_url, None);
}

pub(crate) fn remaining_pending_web_candidates(pending: &PendingSearchCompletion) -> usize {
    let attempted: BTreeSet<String> = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    pending
        .candidate_urls
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && !attempted.contains(*value))
        .count()
}

pub(crate) fn single_snapshot_has_metric_grounding(pending: &PendingSearchCompletion) -> bool {
    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        contains_current_condition_metric_signal(&observed_text)
    })
}

pub(crate) fn single_snapshot_has_viable_followup_candidate(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let projection =
        build_query_constraint_projection(query_contract, 1, &pending.candidate_source_hints);
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let attempted_urls = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();

    pending.candidate_urls.iter().any(|candidate| {
        let trimmed = candidate.trim();
        if trimmed.is_empty() || attempted_urls.contains(trimmed) {
            return false;
        }
        let hint = hint_for_url(pending, trimmed);
        let title = hint
            .and_then(|entry| entry.title.as_deref())
            .unwrap_or_default();
        let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
        let compatibility = candidate_constraint_compatibility(
            envelope_constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            title,
            excerpt,
        );
        if projection.enforce_grounded_compatibility()
            && !compatibility_passes_projection(&projection, &compatibility)
        {
            return false;
        }
        if title.trim().is_empty() && excerpt.trim().is_empty() {
            return false;
        }
        let envelope_score = single_snapshot_candidate_envelope_score(
            envelope_constraints,
            envelope_policy,
            trimmed,
            title,
            excerpt,
        );
        let resolves_constraint =
            envelope_score_resolves_constraint(envelope_constraints, &envelope_score);
        if projection.has_constraint_objective() {
            resolves_constraint
        } else {
            resolves_constraint || compatibility_passes_projection(&projection, &compatibility)
        }
    })
}

pub(crate) fn single_snapshot_probe_budget_allows_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    pending.deadline_ms.saturating_sub(now_ms) >= SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE
}

pub(crate) fn single_snapshot_additional_probe_attempt_count(
    pending: &PendingSearchCompletion,
) -> usize {
    let observed_search_attempts = pending
        .attempted_urls
        .iter()
        .filter(|url| {
            let trimmed = url.trim();
            !trimmed.is_empty() && is_search_hub_url(trimmed)
        })
        .count();
    let baseline_search_attempt_missing_from_attempts = if is_search_hub_url(&pending.url) {
        let pending_search_url = pending.url.trim();
        !pending_search_url.is_empty()
            && !pending.attempted_urls.iter().any(|url| {
                let trimmed = url.trim();
                !trimmed.is_empty() && url_structurally_equivalent(trimmed, pending_search_url)
            })
    } else {
        false
    };
    let total_search_attempts = observed_search_attempts
        .saturating_add(usize::from(baseline_search_attempt_missing_from_attempts));
    let probe_query_delta = usize::from({
        let query = pending.query.trim();
        let query_contract = pending.query_contract.trim();
        total_search_attempts == 0
            && !query.is_empty()
            && !query_contract.is_empty()
            && !query.eq_ignore_ascii_case(query_contract)
    });
    total_search_attempts
        .saturating_sub(1)
        .saturating_add(probe_query_delta)
}

pub(crate) fn single_snapshot_requires_current_metric_observation_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !prefers_single_fact_snapshot(&query_contract) {
        return false;
    }
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources.max(1),
        &pending.candidate_source_hints,
    );
    let has_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty()
        || (projection.query_facets.time_sensitive_public_fact
            && projection.query_facets.locality_sensitive_public_fact);
    let requires_current_observation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || projection.query_facets.time_sensitive_public_fact;
    has_metric_objective && requires_current_observation
}

pub(crate) fn web_pipeline_requires_metric_probe_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if !single_snapshot_requires_current_metric_observation_contract(pending) {
        return false;
    }
    let query_contract = synthesis_query_contract(pending);
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources {
        return false;
    }
    if single_snapshot_has_metric_grounding(pending) {
        return false;
    }
    let snapshot_probe_limit =
        min_sources.saturating_add(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES);
    if pending.successful_reads.len() >= snapshot_probe_limit {
        return false;
    }
    if single_snapshot_additional_probe_attempt_count(pending)
        >= SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
    {
        return false;
    }
    if !single_snapshot_probe_budget_allows_followup(pending, now_ms) {
        return false;
    }
    if single_snapshot_has_viable_followup_candidate(pending, &query_contract) {
        return true;
    }
    // Pre-emit quality gate: allow one deterministic recovery probe even when
    // candidate inventory is exhausted, so the pipeline can self-correct
    // missing current-observation metrics before final reply emission.
    true
}

pub(crate) fn web_pipeline_completion_reason(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> Option<WebPipelineCompletionReason> {
    let query_contract = synthesis_query_contract(pending);
    let required_distinct_source_floor = required_distinct_citations(&query_contract);

    // Ontology-level fallback: if live reads are blocked but ranked source hints already
    // satisfy citation diversity, synthesize from captured evidence instead of churning.
    if pending.successful_reads.is_empty()
        && !pending.blocked_urls.is_empty()
        && pending.candidate_source_hints.len() >= required_distinct_source_floor
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    let single_snapshot_mode = prefers_single_fact_snapshot(&query_contract);
    let query_facets = analyze_query_facets(&query_contract);
    let remaining_candidates = remaining_pending_web_candidates(pending);
    let has_viable_followup_candidate =
        single_snapshot_has_viable_followup_candidate(pending, &query_contract);
    let min_sources = pending.min_sources.max(1) as usize;
    let grounded_sources = grounded_source_evidence_count(pending);

    if single_snapshot_mode
        && pending.successful_reads.len() >= 1
        && pending.successful_reads.len() < min_sources
        && grounded_sources >= min_sources
        && !single_snapshot_has_metric_grounding(pending)
        && !has_viable_followup_candidate
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    if pending.successful_reads.len() >= min_sources {
        if single_snapshot_mode && web_pipeline_requires_metric_probe_followup(pending, now_ms) {
            return None;
        }
        if single_snapshot_mode && !single_snapshot_has_metric_grounding(pending) {
            let post_probe_attempt_available =
                single_snapshot_additional_probe_attempt_count(pending) > 0;
            if post_probe_attempt_available
                && remaining_candidates > 0
                && next_pending_web_candidate(pending).is_some()
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if remaining_candidates == 0 {
        let grounded_probe_limit = required_distinct_source_floor
            .max(min_sources)
            .max(1)
            .saturating_sub(1)
            .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX as usize);
        let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
            true
        } else {
            pending.deadline_ms.saturating_sub(now_ms)
                >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
        };
        let grounded_probe_recovery = !single_snapshot_mode
            && query_facets.grounded_external_required
            && pending.successful_reads.len() < min_sources
            && single_snapshot_additional_probe_attempt_count(pending)
                < grounded_probe_limit
            && grounded_probe_budget_allows;
        if grounded_probe_recovery {
            return None;
        }
        // Keep the loop alive for one bounded probe when the citation/source floor
        // is still unmet in single-snapshot mode and budget allows recovery.
        if single_snapshot_mode
            && pending.successful_reads.len() < min_sources
            && single_snapshot_additional_probe_attempt_count(pending)
                < SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
            && single_snapshot_probe_budget_allows_followup(pending, now_ms)
        {
            return None;
        }
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }
    None
}

pub(crate) fn queue_web_read_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    url: &str,
) -> Result<bool, TransactionError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({ "url": trimmed }))
        .or_else(|_| serde_json::to_vec(&json!({ "url": trimmed })))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn queue_web_search_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
    limit: u32,
) -> Result<bool, TransactionError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "query": trimmed,
        "limit": limit.max(1),
    }))
    .or_else(|_| {
        serde_json::to_vec(&json!({
            "query": trimmed,
            "limit": limit.max(1),
        }))
    })
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }
    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn is_human_challenge_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("error_class=humanchallengerequired")
        || lower.contains("recaptcha")
        || lower.contains("human verification")
        || lower.contains("verify you are human")
        || lower.contains("i'm not a robot")
        || lower.contains("i am not a robot")
}
