use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;
use std::collections::BTreeSet;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, is_timeout_terminal, truncate_chars, verification_bool, verification_u64,
    verification_value, verification_values, ExecutionProfile, LocalCheck, LocalJudgeResult,
    QueryCase, RunObservation,
};

const CASE_ID: &str = "check_which_apps_are_using_the_most_memory_right_now_and_list_them";
const EXPECTED_FIXTURE_MODE: &str = "top_memory_apps_fixture_v1";
const MIN_REQUIRED_ROWS: usize = 3;

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

#[derive(Debug, Clone)]
struct TopMemoryRow {
    rank: usize,
    app: String,
    pid: u32,
    rss_kb: u64,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: concat!(
            "Check which apps are using the most memory right now and list them. ",
            "Use exactly one `sys__exec` invocation to run \"{TOP_MEMORY_APPS_PROBE_PATH} 5\". ",
            "Do not use shell fallback chains, web, browser, net, filesystem mutation, or install tools. ",
            "The probe prints strict receipt lines in this format: `provider=<id>` and `row|rank|app|pid|rss_kb`. ",
            "List the top apps in descending memory order and include app name, pid, and rss_kb for each listed row."
        ),
        success_definition: "Discover top memory-consuming apps through the fixture-backed command execution probe, list them in descending RSS order, and satisfy CEC/contract/environment/cleanup evidence receipts without fallback behavior.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 8,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: true,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode =
        verification_value(obs, "env_receipt::top_memory_apps_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::top_memory_apps_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::top_memory_apps_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_fixture_satisfied").unwrap_or(false);
    let run_unique_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_run_unique_satisfied")
            .unwrap_or(false);
    let probe_script_seeded_satisfied = verification_bool(
        obs,
        "env_receipt::top_memory_apps_probe_script_seeded_satisfied",
    )
    .unwrap_or(false);

    let probe_script_path =
        verification_value(obs, "env_receipt::top_memory_apps_probe_script_path")
            .unwrap_or_default();

    let provider =
        verification_value(obs, "env_receipt::top_memory_apps_provider").unwrap_or_default();
    let provider_probe_source =
        verification_value(obs, "env_receipt::top_memory_apps_provider_probe_source")
            .unwrap_or_default();
    let provider_timestamp_ms =
        verification_u64(obs, "env_receipt::top_memory_apps_provider_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let provider_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_provider_satisfied").unwrap_or(false)
            && provider.eq_ignore_ascii_case("ps");

    let row_markers = verification_values(obs, "env_receipt::top_memory_apps_row");
    let rows = parse_top_memory_rows(&row_markers);
    let row_count = rows.len();
    let row_count_receipt =
        verification_u64(obs, "env_receipt::top_memory_apps_row_count").unwrap_or(0) as usize;
    let row_count_probe_source =
        verification_value(obs, "env_receipt::top_memory_apps_row_count_probe_source")
            .unwrap_or_default();
    let row_count_timestamp_ms =
        verification_u64(obs, "env_receipt::top_memory_apps_row_count_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let row_count_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_row_count_satisfied").unwrap_or(false);
    let rows_sorted_receipt_satisfied = verification_bool(
        obs,
        "env_receipt::top_memory_apps_rows_sorted_desc_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_scope_satisfied").unwrap_or(false);
    let rows_sorted_runtime_satisfied = rows_are_ranked_and_sorted_desc(&rows);

    let cleanup_probe_source =
        verification_value(obs, "env_receipt::top_memory_apps_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::top_memory_apps_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::top_memory_apps_cleanup_satisfied").unwrap_or(false);

    let probe_command_success_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| {
            entry.exit_code == 0 && command_matches_probe(&entry.command, &probe_script_path)
        })
        .count();
    let non_probe_command_count = obs
        .command_history_evidence
        .iter()
        .filter(|entry| !command_matches_probe(&entry.command, &probe_script_path))
        .count();

    let exec_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_exec_action_success(entry))
        .count();
    let hard_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| action_has_hard_error_class(entry))
        .count();
    let exec_action_hard_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| entry.tool_name.eq_ignore_ascii_case("sys__exec"))
        .filter(|entry| action_has_hard_error_class(entry))
        .count();
    let timeout_terminal = is_timeout_terminal(obs);

    let reply_mentions_top_rows = response_mentions_top_rows(&obs.final_reply, &rows);
    let required_reply_mentions = rows.iter().take(3).count().clamp(1, 2);
    let reply_has_memory_context = {
        let lower = obs.final_reply.to_ascii_lowercase();
        lower.contains("memory")
            || lower.contains("rss")
            || lower.contains("ram")
            || lower.contains("kb")
    };
    let reply_alignment_satisfied =
        reply_mentions_top_rows >= required_reply_mentions && reply_has_memory_context;

    let objective_specific_top_memory_apps_evidence_present = provider_satisfied
        && scope_satisfied
        && row_count_satisfied
        && rows_sorted_receipt_satisfied
        && row_count >= MIN_REQUIRED_ROWS
        && row_count == row_count_receipt
        && rows_sorted_runtime_satisfied
        && probe_command_success_count == 1
        && non_probe_command_count == 0
        && (reply_alignment_satisfied || timeout_terminal);

    let action_exec_path_seen = has_tool_with_token(&obs.action_tools, "sys__exec");
    let routing_exec_path_seen = has_tool_with_token(&obs.routing_tools, "sys__exec");
    let exec_session_seen = has_tool_with_token(&obs.action_tools, "sys__exec_session")
        || has_tool_with_token(&obs.routing_tools, "sys__exec_session");
    let remote_path_seen = has_tool_with_token(&obs.action_tools, "web__")
        || has_tool_with_token(&obs.routing_tools, "web__")
        || has_tool_with_token(&obs.workload_tools, "web__")
        || has_tool_with_token(&obs.action_tools, "browser__")
        || has_tool_with_token(&obs.routing_tools, "browser__")
        || has_tool_with_token(&obs.workload_tools, "browser__")
        || has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch")
        || has_tool_with_token(&obs.workload_tools, "net__fetch");
    let install_tool_seen = has_tool_with_token(&obs.action_tools, "sys__install_package")
        || has_tool_with_token(&obs.routing_tools, "sys__install_package")
        || has_tool_with_token(&obs.workload_tools, "sys__install_package");
    let disallowed_mutating_action_seen = has_disallowed_mutating_action(obs);
    let tool_and_route_path_evidence_present = action_exec_path_seen
        && routing_exec_path_seen
        && !exec_session_seen
        && !remote_path_seen
        && !install_tool_seen
        && !disallowed_mutating_action_seen;

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            || has_cec_receipt(obs, "verification", "verification_commit", Some(true))
            || has_cec_receipt(
                obs,
                "provider_selection",
                "provider_selection_commit",
                Some(true),
            );
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen
        && cec_postcondition_seen
        && (cec_contract_gate_seen || obs.completed || timeout_terminal);

    let any_contract_failure_marker = has_contract_failure_evidence(obs);
    let contract_failure_markers_absent = !any_contract_failure_marker
        && exec_action_hard_failure_count == 0
        && (!timeout_terminal || objective_specific_top_memory_apps_evidence_present);

    let completion_evidence_present = (obs.completed
        && !obs.failed
        && (!obs.final_reply.trim().is_empty()
            || obs.chat_reply_count > 0
            || objective_specific_top_memory_apps_evidence_present)
        && exec_action_success_count >= 1)
        || (timeout_terminal
            && objective_specific_top_memory_apps_evidence_present
            && cec_phase_receipts_present
            && !any_contract_failure_marker);

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        run_unique_satisfied,
        probe_script_seeded_satisfied,
        provider,
        provider_probe_source,
        provider_timestamp_ms,
        provider_satisfied,
        row_count,
        row_count_receipt,
        rows_sorted_runtime_satisfied,
        rows_sorted_receipt_satisfied,
        row_count_probe_source,
        row_count_timestamp_ms,
        row_markers,
        probe_command_success_count,
        non_probe_command_count,
        cec_phase_receipts_present,
        timeout_terminal,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_top_memory_apps_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        contract_failure_markers_absent,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_top_memory_apps_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} reply_len={} exec_action_success_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                obs.final_reply.chars().count(),
                exec_action_success_count,
            ),
        ),
        LocalCheck::new(
            "objective_specific_top_memory_apps_evidence_present",
            objective_specific_top_memory_apps_evidence_present,
            format!(
                "provider_satisfied={} row_count={} row_count_receipt={} rows_sorted_runtime_satisfied={} rows_sorted_receipt_satisfied={} probe_command_success_count={} non_probe_command_count={} reply_mentions_top_rows={} required_reply_mentions={} reply_has_memory_context={}",
                provider_satisfied,
                row_count,
                row_count_receipt,
                rows_sorted_runtime_satisfied,
                rows_sorted_receipt_satisfied,
                probe_command_success_count,
                non_probe_command_count,
                reply_mentions_top_rows,
                required_reply_mentions,
                reply_has_memory_context,
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} exec_session_seen={} remote_path_seen={} install_tool_seen={} disallowed_mutating_action_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                exec_session_seen,
                remote_path_seen,
                install_tool_seen,
                disallowed_mutating_action_seen,
            ),
        ),
        LocalCheck::new(
            "cec_phase_receipts_present",
            cec_phase_receipts_present,
            format!(
                "discovery={} provider_selection={} execution={} verification={} postcondition={} contract_gate={} cec_receipts={:?}",
                cec_discovery_seen,
                cec_provider_selection_seen,
                cec_execution_seen,
                cec_verification_seen,
                cec_postcondition_seen,
                cec_contract_gate_seen,
                obs.cec_receipts,
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            truncate_chars(
                &format!(
                    "hard_action_failure_count={} verification_checks={:?} final_reply={} event_excerpt={:?}",
                    hard_action_failure_count,
                    obs.verification_checks,
                    obs.final_reply,
                    obs.event_excerpt,
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_top_memory_apps_evidence_present={}",
                independent_channel_count, objective_specific_top_memory_apps_evidence_present,
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    run_unique_satisfied: bool,
    probe_script_seeded_satisfied: bool,
    provider: String,
    provider_probe_source: String,
    provider_timestamp_ms: u64,
    provider_satisfied: bool,
    row_count: usize,
    row_count_receipt: usize,
    rows_sorted_runtime_satisfied: bool,
    rows_sorted_receipt_satisfied: bool,
    row_count_probe_source: String,
    row_count_timestamp_ms: u64,
    row_markers: Vec<String>,
    probe_command_success_count: usize,
    non_probe_command_count: usize,
    cec_phase_receipts_present: bool,
    timeout_terminal: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied
                && run_unique_satisfied
                && probe_script_seeded_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_provider_observed",
            observed_value: provider,
            probe_source: provider_probe_source,
            timestamp_ms: provider_timestamp_ms,
            satisfied: provider_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_rows_observed",
            observed_value: row_markers.join(","),
            probe_source: row_count_probe_source,
            timestamp_ms: row_count_timestamp_ms,
            satisfied: row_count >= MIN_REQUIRED_ROWS
                && row_count == row_count_receipt
                && rows_sorted_runtime_satisfied
                && rows_sorted_receipt_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_probe_command_observed",
            observed_value: format!(
                "probe_command_success_count={} non_probe_command_count={}",
                probe_command_success_count, non_probe_command_count,
            ),
            probe_source: "RunObservation.command_history_evidence".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: probe_command_success_count == 1 && non_probe_command_count == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_cec_receipts_observed",
            observed_value: format!(
                "cec_phase_receipts_present={} timeout_terminal={}",
                cec_phase_receipts_present, timeout_terminal
            ),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "top_memory_apps_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn parse_top_memory_rows(markers: &[String]) -> Vec<TopMemoryRow> {
    let mut rows = markers
        .iter()
        .filter_map(|marker| {
            let mut parts = marker.split('|').map(str::trim);
            let rank = parts.next()?.parse::<usize>().ok()?;
            let app = parts.next()?.to_string();
            let pid = parts.next()?.parse::<u32>().ok()?;
            let rss_kb = parts.next()?.parse::<u64>().ok()?;
            if app.is_empty() || pid == 0 || rss_kb == 0 {
                return None;
            }
            Some(TopMemoryRow {
                rank,
                app,
                pid,
                rss_kb,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.rank);
    rows
}

fn rows_are_ranked_and_sorted_desc(rows: &[TopMemoryRow]) -> bool {
    if rows.len() < MIN_REQUIRED_ROWS {
        return false;
    }

    let mut seen_ranks = BTreeSet::new();
    let mut seen_pids = BTreeSet::new();
    let mut previous_rss: Option<u64> = None;

    for (idx, row) in rows.iter().enumerate() {
        if row.rank != idx + 1 {
            return false;
        }
        if !seen_ranks.insert(row.rank) || !seen_pids.insert(row.pid) {
            return false;
        }
        if let Some(previous) = previous_rss {
            if row.rss_kb > previous {
                return false;
            }
        }
        previous_rss = Some(row.rss_kb);
    }

    true
}

fn response_mentions_top_rows(final_reply: &str, rows: &[TopMemoryRow]) -> usize {
    let reply_lower = final_reply.to_ascii_lowercase();
    rows.iter()
        .take(3)
        .filter(|row| {
            reply_lower.contains(&row.app.to_ascii_lowercase())
                || reply_lower.contains(&row.pid.to_string())
        })
        .count()
}

fn command_matches_probe(command: &str, probe_script_path: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let probe_lower = probe_script_path.to_ascii_lowercase();
    (!probe_lower.is_empty() && lower.contains(&probe_lower))
        || lower.contains("top_memory_apps_probe")
}

fn has_disallowed_mutating_action(obs: &RunObservation) -> bool {
    obs.action_tools.iter().any(|tool| {
        let lower = tool.to_ascii_lowercase();
        lower.contains("filesystem__write_file")
            || lower.contains("filesystem__patch")
            || lower.contains("filesystem__delete_path")
            || lower.contains("filesystem__create_directory")
            || lower.contains("filesystem__create_zip")
            || lower.contains("filesystem__move_path")
            || lower.contains("filesystem__copy_path")
    })
}

fn is_exec_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("sys__exec")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
