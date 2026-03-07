use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, truncate_chars, verification_bool, verification_u64, verification_value,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "uninstall_spotify_and_remove_its_leftover_config_files";
const EXPECTED_FIXTURE_MODE: &str = "spotify_uninstall_fixture_v1";
const EXPECTED_PROVIDER_IDS: [&str; 5] = ["apt-get", "snap", "flatpak", "brew", "pacman"];
const REQUIRED_CONFIG_PATH_COUNT: usize = 3;

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
            "Uninstall Spotify and remove its leftover config files. ",
            "Use the isolated fixture root at \"{SPOTIFY_UNINSTALL_FIXTURE_ROOT}\" and the fixture HOME. ",
            "Use exactly one `sys__exec` invocation that runs a single `sh -lc` command to perform discovery and uninstall in one shot: ",
            "detect first available provider from [apt-get, snap, flatpak, brew, pacman], execute provider uninstall for Spotify, remove ~/.config/spotify ~/.cache/spotify ~/.local/share/spotify, and print `provider=<id>` in stdout. ",
            "Do not use web, browser, or net tools. ",
            "Do not mutate paths outside the fixture HOME. ",
            "No additional command-exec invocations are allowed after that single command."
        ),
        success_definition: "Complete Spotify uninstall and leftover config removal in the isolated fixture environment using command-exec tooling, with CEC discovery/provider/execution/verification/completion receipts, runtime environment receipts, and deterministic cleanup evidence.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 100,
        max_steps: 1,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode =
        verification_value(obs, "env_receipt::spotify_uninstall_fixture_mode").unwrap_or_default();
    let fixture_probe_source =
        verification_value(obs, "env_receipt::spotify_uninstall_fixture_probe_source")
            .unwrap_or_default();
    let fixture_timestamp_ms =
        verification_u64(obs, "env_receipt::spotify_uninstall_fixture_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::spotify_uninstall_fixture_satisfied").unwrap_or(false);

    let provider =
        verification_value(obs, "env_receipt::spotify_uninstall_provider").unwrap_or_default();
    let provider_probe_source =
        verification_value(obs, "env_receipt::spotify_uninstall_provider_probe_source")
            .unwrap_or_default();
    let provider_timestamp_ms =
        verification_u64(obs, "env_receipt::spotify_uninstall_provider_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let provider_receipt_satisfied =
        verification_bool(obs, "env_receipt::spotify_uninstall_provider_satisfied")
            .unwrap_or(false);
    let provider_allowed = EXPECTED_PROVIDER_IDS
        .iter()
        .any(|expected| provider.eq_ignore_ascii_case(expected));
    let provider_satisfied = provider_allowed && provider_receipt_satisfied;

    let install_marker_path =
        verification_value(obs, "env_receipt::spotify_uninstall_install_marker_path")
            .unwrap_or_default();
    let install_marker_removed_satisfied = verification_bool(
        obs,
        "env_receipt::spotify_uninstall_install_marker_removed_satisfied",
    )
    .unwrap_or(false);

    let binary_path =
        verification_value(obs, "env_receipt::spotify_uninstall_binary_path").unwrap_or_default();
    let binary_absent_satisfied = verification_bool(
        obs,
        "env_receipt::spotify_uninstall_binary_absent_satisfied",
    )
    .unwrap_or(false);

    let config_paths_csv =
        verification_value(obs, "env_receipt::spotify_uninstall_config_paths").unwrap_or_default();
    let config_paths_removed_satisfied = verification_bool(
        obs,
        "env_receipt::spotify_uninstall_config_paths_removed_satisfied",
    )
    .unwrap_or(false);
    let fixture_home_dir =
        verification_value(obs, "env_receipt::spotify_uninstall_fixture_home_dir")
            .unwrap_or_default();
    let config_paths = config_paths_csv
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let config_paths_shape_satisfied = config_paths.len() == REQUIRED_CONFIG_PATH_COUNT
        && !fixture_home_dir.is_empty()
        && config_paths
            .iter()
            .all(|path| path.starts_with(fixture_home_dir.as_str()));

    let scope_satisfied =
        verification_bool(obs, "env_receipt::spotify_uninstall_scope_satisfied").unwrap_or(false);

    let cleanup_probe_source =
        verification_value(obs, "env_receipt::spotify_uninstall_cleanup_probe_source")
            .unwrap_or_default();
    let cleanup_timestamp_ms =
        verification_u64(obs, "env_receipt::spotify_uninstall_cleanup_timestamp_ms")
            .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::spotify_uninstall_cleanup_satisfied").unwrap_or(false);

    let exec_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| is_exec_action_success(entry))
        .count();

    let action_exec_path_seen = has_tool_with_token(&obs.action_tools, "sys__exec");
    let routing_exec_path_seen = has_tool_with_token(&obs.routing_tools, "sys__exec");
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
    let tool_and_route_path_evidence_present =
        action_exec_path_seen && routing_exec_path_seen && !remote_path_seen && !install_tool_seen;

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_postcondition_seen =
        has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
            || has_cec_receipt(obs, "verification", "verification_commit", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_phase_receipts_present = cec_discovery_seen
        && cec_provider_selection_seen
        && cec_execution_seen
        && cec_verification_seen
        && cec_postcondition_seen
        && (cec_contract_gate_seen || obs.completed);

    let completion_evidence_present =
        obs.completed && !obs.failed && (!obs.action_evidence.is_empty() || cec_contract_gate_seen);

    let objective_specific_uninstall_evidence_present = provider_satisfied
        && install_marker_removed_satisfied
        && binary_absent_satisfied
        && config_paths_removed_satisfied
        && config_paths_shape_satisfied
        && scope_satisfied
        && exec_action_success_count == 1;

    let any_contract_failure_marker = has_contract_failure_evidence(obs);

    let environment_receipts = vec![
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: fixture_probe_source,
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_provider_observed",
            observed_value: provider.clone(),
            probe_source: provider_probe_source,
            timestamp_ms: provider_timestamp_ms,
            satisfied: provider_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_install_marker_observed",
            observed_value: install_marker_path,
            probe_source: "harness.spotify_uninstall_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: install_marker_removed_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_binary_absent_observed",
            observed_value: binary_path,
            probe_source: "harness.spotify_uninstall_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: binary_absent_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_config_paths_observed",
            observed_value: config_paths_csv,
            probe_source: "harness.spotify_uninstall_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: config_paths_removed_satisfied && config_paths_shape_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_scope_observed",
            observed_value: format!("scope_satisfied={}", scope_satisfied),
            probe_source: "harness.spotify_uninstall_fixture.fs_probe".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_cec_receipts_observed",
            observed_value: format!("cec_phase_receipts_present={}", cec_phase_receipts_present),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: cec_phase_receipts_present,
        },
        EnvironmentEvidenceReceipt {
            key: "spotify_uninstall_cleanup_observed",
            observed_value: format!("cleanup_satisfied={}", cleanup_satisfied),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied,
        },
    ];
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_uninstall_evidence_present,
        tool_and_route_path_evidence_present,
        cec_phase_receipts_present,
        environment_receipts_satisfied,
        !any_contract_failure_marker,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_uninstall_evidence_present && independent_channel_count >= 5;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} reply_len={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                obs.final_reply.chars().count()
            ),
        ),
        LocalCheck::new(
            "objective_specific_spotify_uninstall_evidence_present",
            objective_specific_uninstall_evidence_present,
            format!(
                "provider_satisfied={} install_marker_removed_satisfied={} binary_absent_satisfied={} config_paths_removed_satisfied={} config_paths_shape_satisfied={} scope_satisfied={} exec_action_success_count={}",
                provider_satisfied,
                install_marker_removed_satisfied,
                binary_absent_satisfied,
                config_paths_removed_satisfied,
                config_paths_shape_satisfied,
                scope_satisfied,
                exec_action_success_count,
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?} remote_path_seen={} install_tool_seen={}",
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools,
                remote_path_seen,
                install_tool_seen,
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
                obs.cec_receipts
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
                "independent_channel_count={} objective_specific_uninstall_evidence_present={}",
                independent_channel_count, objective_specific_uninstall_evidence_present,
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_exec_action_success(entry: &super::super::types::ActionEvidence) -> bool {
    entry.tool_name.eq_ignore_ascii_case("sys__exec")
        && !entry.agent_status.eq_ignore_ascii_case("failed")
        && !action_has_hard_error_class(entry)
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}
