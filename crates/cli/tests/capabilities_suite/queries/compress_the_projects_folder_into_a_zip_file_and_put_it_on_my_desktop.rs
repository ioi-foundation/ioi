use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "compress_the_projects_folder_into_a_zip_file_and_put_it_on_my_desktop";
const EXPECTED_FIXTURE_MODE: &str = "desktop_projects_zip_fixture_v1";
const EXPECTED_ARCHIVE_NAME: &str = "projects.zip";
const EXPECTED_ARCHIVE_ENTRIES: [&str; 3] = ["README.md", "docs/spec.txt", "src/main.rs"];

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: concat!(
            "Compress the \"Projects\" folder into a zip file and put it on my desktop. ",
            "For deterministic repeatable testing, operate only on \"~/Projects\" as source and ",
            "\"~/Desktop/Projects.zip\" as destination in the harness-provisioned fixture environment. ",
            "Use deterministic filesystem operations (file__zip and filesystem metadata checks) ",
            "and do not invoke shell__run/shell__start for compression. ",
            "After archive creation, verify the archive members include README.md, src/main.rs, and docs/spec.txt, ",
            "then return a concise completion summary."
        ),
        success_definition: "Create ~/Desktop/Projects.zip from ~/Projects using deterministic filesystem zip tooling, verify expected archive members and fixture evidence (including cleanup), and complete without contract failures.",
        seeded_intent_id: "workspace.ops.archive_local_directory",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let zip_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_zip_action_success(entry))
        .count();
    let zip_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_zip_action_failure(entry))
        .count();

    let cec_contract_gate_seen = has_cec_completion_gate_evidence(obs);

    let fixture_mode =
        verification_value(obs, "env_evidence::projects_zip_fixture_mode").unwrap_or_default();
    let fixture_mode_satisfied = fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE);
    let fixture_probe_source =
        verification_value(obs, "env_evidence::projects_zip_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_evidence::projects_zip_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_evidence::projects_zip_fixture_satisfied").unwrap_or(false);

    let archive_path =
        verification_value(obs, "env_evidence::projects_zip_archive_path").unwrap_or_default();
    let archive_probe_source =
        verification_value(obs, "env_evidence::projects_zip_archive_probe_source")
            .unwrap_or_default();
    let archive_timestamp_ms =
        verification_u64(obs, "env_evidence::projects_zip_archive_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let archive_satisfied =
        verification_bool(obs, "env_evidence::projects_zip_archive_satisfied").unwrap_or(false);
    let archive_name_satisfied = archive_path
        .to_ascii_lowercase()
        .ends_with(&format!("/{}", EXPECTED_ARCHIVE_NAME));

    let entries_csv =
        verification_value(obs, "env_evidence::projects_zip_entries").unwrap_or_default();
    let entries_probe_source =
        verification_value(obs, "env_evidence::projects_zip_entries_probe_source")
            .unwrap_or_default();
    let entries_timestamp_ms =
        verification_u64(obs, "env_evidence::projects_zip_entries_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let entries_satisfied =
        verification_bool(obs, "env_evidence::projects_zip_entries_satisfied").unwrap_or(false);
    let entry_list = entries_csv
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let expected_entries_present = EXPECTED_ARCHIVE_ENTRIES.iter().all(|entry| {
        entry_list
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(entry))
    });

    let cleanup_probe_source =
        verification_value(obs, "env_evidence::projects_zip_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_evidence::projects_zip_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_evidence::projects_zip_cleanup_satisfied").unwrap_or(false);
    let source_preserved =
        verification_bool(obs, "env_evidence::projects_zip_source_preserved_satisfied")
            .unwrap_or(false);

    let action_path_seen = has_tool_with_token(&obs.action_tools, "file__zip");
    let routing_path_seen = has_tool_with_token(&obs.routing_tools, "file__zip");
    let sys_exec_path_seen = has_tool_with_token(&obs.action_tools, "shell__run")
        || has_tool_with_token(&obs.routing_tools, "shell__run")
        || has_tool_with_token(&obs.action_tools, "shell__start")
        || has_tool_with_token(&obs.routing_tools, "shell__start");
    let tool_and_route_path_evidence_present =
        action_path_seen && routing_path_seen && !sys_exec_path_seen;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let completion_evidence_present = obs.completed
        && !obs.failed
        && obs.chat_reply_count > 0
        && zip_action_success_count > 0
        && zip_action_failure_count == 0;
    let objective_specific_zip_evidence_present = zip_action_success_count > 0
        && zip_action_failure_count == 0
        && fixture_mode_satisfied
        && fixture_satisfied
        && archive_satisfied
        && archive_name_satisfied
        && entries_satisfied
        && expected_entries_present
        && source_preserved;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_mode_satisfied,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        archive_path,
        archive_probe_source,
        archive_timestamp_ms,
        archive_satisfied && archive_name_satisfied,
        entries_csv,
        entries_probe_source,
        entries_timestamp_ms,
        entries_satisfied && expected_entries_present,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
        source_preserved,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_zip_evidence_present,
        tool_and_route_path_evidence_present,
        cec_contract_gate_seen,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_zip_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} zip_action_success_count={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                zip_action_success_count
            ),
        ),
        LocalCheck::new(
            "objective_specific_zip_evidence_present",
            objective_specific_zip_evidence_present,
            format!(
                "zip_action_success_count={} zip_action_failure_count={} fixture_mode_satisfied={} fixture_satisfied={} archive_satisfied={} archive_name_satisfied={} entries_satisfied={} expected_entries_present={} source_preserved={}",
                zip_action_success_count,
                zip_action_failure_count,
                fixture_mode_satisfied,
                fixture_satisfied,
                archive_satisfied,
                archive_name_satisfied,
                entries_satisfied,
                expected_entries_present,
                source_preserved
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} sys_exec_path_seen={}",
                obs.action_tools, obs.routing_tools, sys_exec_path_seen
            ),
        ),
        LocalCheck::new(
            "cec_contract_evidence_present",
            cec_contract_gate_seen,
            format!(
                "cec_completion_gate_seen={} event_excerpt={:?}",
                cec_contract_gate_seen, obs.event_excerpt
            ),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker,
            truncate_chars(
                &format!(
                    "verification_checks={:?} final_reply={} event_excerpt={:?}",
                    obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                280,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_zip_evidence_present={}",
                independent_channel_count, objective_specific_zip_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_zip_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__zip")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn is_zip_action_failure(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("file__zip")
        && (entry.agent_status.eq_ignore_ascii_case("failed") || action_has_hard_error_class(entry))
}

fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_mode_satisfied: bool,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    archive_path: String,
    archive_probe_source: String,
    archive_timestamp_ms: u64,
    archive_satisfied: bool,
    entries_csv: String,
    entries_probe_source: String,
    entries_timestamp_ms: u64,
    entries_satisfied: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
    source_preserved: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "projects_zip_fixture_mode",
            observed_value: format!("fixture_mode={}", fixture_mode),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode_satisfied && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "projects_zip_archive_created",
            observed_value: format!("archive_path={}", archive_path),
            probe_source: archive_probe_source,
            timestamp_ms: archive_timestamp_ms,
            satisfied: archive_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "projects_zip_expected_entries_present",
            observed_value: format!("entries={}", entries_csv),
            probe_source: entries_probe_source,
            timestamp_ms: entries_timestamp_ms,
            satisfied: entries_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "projects_zip_source_preserved",
            observed_value: format!("source_preserved={}", source_preserved),
            probe_source: "harness.projects_zip_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: source_preserved,
        },
        EnvironmentEvidenceReceipt {
            key: "projects_zip_fixture_cleanup",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ]
}

fn serialize_environment_receipts(evidence: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(evidence).unwrap_or_else(|_| "[]".to_string())
}

fn has_cec_completion_gate_evidence(obs: &RunObservation) -> bool {
    has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true))
}
