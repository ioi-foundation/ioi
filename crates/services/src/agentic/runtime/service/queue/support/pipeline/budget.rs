use super::*;

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
