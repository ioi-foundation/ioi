use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    action_has_hard_error_class, has_cec_receipt, has_cec_stage, has_contract_failure_evidence,
    has_tool_with_token, observation_has_tool_name, truncate_chars, verification_bool,
    verification_u64, verification_value, ExecutionProfile, LocalCheck, LocalJudgeResult,
    QueryCase, RunObservation,
};

const CASE_ID: &str =
    "monitor_hacker_news_and_notify_me_whenever_a_post_about_web4_or_post_quantum_cryptography_hits_the_front_page";
const EXPECTED_FIXTURE_MODE: &str = "hacker_news_front_page_monitor_fixture_v1";
const EXPECTED_SOURCE_URL: &str = "https://news.ycombinator.com/";
const EXPECTED_KEYWORDS_NORMALIZED: &str = "post-quantum cryptography|web4";
const EXPECTED_POLL_INTERVAL_SECONDS: u64 = 300;

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: concat!(
            "Monitor Hacker News and notify me whenever a post about \"Web4\" or ",
            "\"post-quantum cryptography\" hits the front page. ",
            "For deterministic repeatable testing, install this as a durable local automation workflow. ",
            "Use exactly one `automation__create_monitor` tool call with the requested keywords, ",
            "set `interval_seconds` to 300, and preserve the user request in `source_prompt`. ",
            "Do not use `sys__exec`/`sys__exec_session`, web, browser, net, install, or filesystem mutation tools. ",
            "Return a concise completion summary with the installed workflow id and poll interval."
        ),
        success_definition: "Install a durable Hacker News monitor workflow through the automation pipeline, write the workflow artifact/state/install receipt under the isolated automation root, and complete only after CEC receipts and fixture receipts confirm the install semantics.",
        seeded_intent_id: "automation.monitor",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 120,
        max_steps: 6,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode = verification_value(obs, "env_receipt::hacker_news_monitor_fixture_mode")
        .unwrap_or_default();
    let fixture_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_fixture_satisfied")
            .unwrap_or(false);
    let run_unique_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_run_unique_satisfied")
            .unwrap_or(false);
    let automation_root_seeded_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_automation_root_seeded_satisfied",
    )
    .unwrap_or(false);
    let manifest_seeded_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_fixture_manifest_seeded_satisfied",
    )
    .unwrap_or(false);
    let registry_absent_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_registry_absent_satisfied")
            .unwrap_or(false);
    let receipts_absent_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_receipts_absent_satisfied")
            .unwrap_or(false);
    let cleanup_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_cleanup_satisfied")
            .unwrap_or(false);

    let workflow_id =
        verification_value(obs, "env_receipt::hacker_news_monitor_workflow_id").unwrap_or_default();
    let registry_count =
        verification_u64(obs, "env_receipt::hacker_news_monitor_registry_count").unwrap_or(0);
    let registry_path_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_registry_path_satisfied")
            .unwrap_or(false);
    let workflow_status =
        verification_value(obs, "env_receipt::hacker_news_monitor_workflow_status")
            .unwrap_or_default();
    let workflow_status_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_workflow_status_satisfied",
    )
    .unwrap_or(false);
    let artifact_path_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_artifact_path_satisfied")
            .unwrap_or(false);
    let state_path_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_state_path_satisfied")
            .unwrap_or(false);
    let install_receipt_path_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_install_receipt_path_satisfied",
    )
    .unwrap_or(false);
    let spec_version =
        verification_value(obs, "env_receipt::hacker_news_monitor_spec_version")
            .unwrap_or_default();
    let spec_version_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_spec_version_satisfied")
            .unwrap_or(false);
    let source_url =
        verification_value(obs, "env_receipt::hacker_news_monitor_source_url").unwrap_or_default();
    let source_url_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_source_url_satisfied")
            .unwrap_or(false);
    let source_type =
        verification_value(obs, "env_receipt::hacker_news_monitor_source_type").unwrap_or_default();
    let source_type_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_source_type_satisfied")
            .unwrap_or(false);
    let extractor_type = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_extractor_type",
    )
    .unwrap_or_default();
    let extractor_type_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_extractor_type_satisfied",
    )
    .unwrap_or(false);
    let extractor_selector = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_extractor_selector",
    )
    .unwrap_or_default();
    let extractor_selector_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_extractor_selector_satisfied",
    )
    .unwrap_or(false);
    let predicate_type = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_predicate_type",
    )
    .unwrap_or_default();
    let predicate_type_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_predicate_type_satisfied",
    )
    .unwrap_or(false);
    let keywords_normalized = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_keywords_normalized",
    )
    .unwrap_or_default();
    let keywords_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_keywords_normalized_satisfied",
    )
    .unwrap_or(false);
    let poll_interval_seconds = verification_u64(
        obs,
        "env_receipt::hacker_news_monitor_poll_interval_seconds",
    )
    .unwrap_or(0);
    let poll_interval_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_poll_interval_seconds_satisfied",
    )
    .unwrap_or(false);
    let sink_type =
        verification_value(obs, "env_receipt::hacker_news_monitor_sink_type").unwrap_or_default();
    let sink_rail =
        verification_value(obs, "env_receipt::hacker_news_monitor_sink_rail").unwrap_or_default();
    let sink_notification_class = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_sink_notification_class",
    )
    .unwrap_or_default();
    let sink_type_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_sink_type_satisfied")
            .unwrap_or(false);
    let sink_rail_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_sink_rail_satisfied")
            .unwrap_or(false);
    let sink_notification_class_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_sink_notification_class_satisfied",
    )
    .unwrap_or(false);
    let allowlist_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_allowlist_satisfied")
            .unwrap_or(false);
    let graph_shape_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_graph_shape_satisfied")
            .unwrap_or(false);
    let next_run_at_ms =
        verification_u64(obs, "env_receipt::hacker_news_monitor_next_run_at_ms").unwrap_or(0);
    let next_run_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_next_run_at_ms_satisfied")
            .unwrap_or(false);
    let state_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_state_satisfied")
            .unwrap_or(false);
    let state_seen_key_count = verification_u64(
        obs,
        "env_receipt::hacker_news_monitor_state_seen_key_count",
    )
    .unwrap_or(0);
    let state_last_run_ms = verification_u64(
        obs,
        "env_receipt::hacker_news_monitor_state_last_run_ms",
    )
    .unwrap_or(u64::MAX);
    let state_last_success_ms = verification_u64(
        obs,
        "env_receipt::hacker_news_monitor_state_last_success_ms",
    )
    .unwrap_or(u64::MAX);
    let state_failure_count = verification_u64(
        obs,
        "env_receipt::hacker_news_monitor_state_failure_count",
    )
    .unwrap_or(u64::MAX);
    let install_receipt_satisfied = verification_bool(
        obs,
        "env_receipt::hacker_news_monitor_install_receipt_satisfied",
    )
    .unwrap_or(false);
    let install_authoring_tool = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_install_authoring_tool",
    )
    .unwrap_or_default();
    let install_trigger_kind = verification_value(
        obs,
        "env_receipt::hacker_news_monitor_install_trigger_kind",
    )
    .unwrap_or_default();
    let install_valid =
        verification_value(obs, "env_receipt::hacker_news_monitor_install_valid")
            .unwrap_or_default();
    let source_prompt_satisfied =
        verification_bool(obs, "env_receipt::hacker_news_monitor_source_prompt_satisfied")
            .unwrap_or(false);

    let automation_plans = obs
        .planned_tool_calls
        .iter()
        .filter(|call| call.tool_name.eq_ignore_ascii_case("automation__create_monitor"))
        .collect::<Vec<_>>();
    let automation_plan_count = automation_plans.len();
    let planned_keywords = automation_plans
        .first()
        .and_then(|call| call.arguments.get("keywords"))
        .and_then(|value| value.as_array())
        .map(|values| {
            let mut normalized = values
                .iter()
                .filter_map(|value| value.as_str())
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            normalized.sort();
            normalized.dedup();
            normalized.join("|")
        })
        .unwrap_or_default();
    let planned_interval_seconds = automation_plans
        .first()
        .and_then(|call| call.arguments.get("interval_seconds"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let planned_source_prompt_present = automation_plans
        .first()
        .and_then(|call| call.arguments.get("source_prompt"))
        .and_then(|value| value.as_str())
        .map(|value| value.contains("Monitor Hacker News"))
        .unwrap_or(false);

    let automation_action_success_count = obs
        .action_evidence
        .iter()
        .filter(|entry| {
            entry.tool_name.eq_ignore_ascii_case("automation__create_monitor")
                && entry.error_class.is_none()
        })
        .count();
    let hard_action_failure_count = obs
        .action_evidence
        .iter()
        .filter(|entry| action_has_hard_error_class(entry))
        .count();

    let automation_tool_seen = observation_has_tool_name(obs, "automation__create_monitor");
    let shell_exec_seen = has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec")
        || has_tool_with_token(&obs.workload_tools, "sys__exec");
    let exec_session_seen = has_tool_with_token(&obs.action_tools, "sys__exec_session")
        || has_tool_with_token(&obs.routing_tools, "sys__exec_session")
        || has_tool_with_token(&obs.workload_tools, "sys__exec_session");
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
    let filesystem_tool_seen = has_tool_with_token(&obs.action_tools, "filesystem__")
        || has_tool_with_token(&obs.routing_tools, "filesystem__")
        || has_tool_with_token(&obs.workload_tools, "filesystem__");

    let cec_discovery_seen = has_cec_stage(obs, "discovery", Some(true));
    let cec_provider_selection_seen = has_cec_stage(obs, "provider_selection", Some(true));
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            obs.completed && !obs.failed && cec_contract_gate_seen,
            format!("status={} failed={}", obs.final_status, obs.failed),
        ),
        LocalCheck::new(
            "automation_tool_path_seen",
            automation_tool_seen && automation_action_success_count == 1 && automation_plan_count == 1,
            format!(
                "action_tools={:?} planned_calls={} action_successes={}",
                obs.action_tools, automation_plan_count, automation_action_success_count
            ),
        ),
        LocalCheck::new(
            "no_shell_or_remote_fallback_path",
            !shell_exec_seen
                && !exec_session_seen
                && !remote_path_seen
                && !install_tool_seen
                && !filesystem_tool_seen,
            format!(
                "routing_tools={:?} workload_tools={:?}",
                obs.routing_tools, obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "automation_plan_arguments_present",
            planned_keywords == EXPECTED_KEYWORDS_NORMALIZED
                && planned_interval_seconds == EXPECTED_POLL_INTERVAL_SECONDS
                && planned_source_prompt_present,
            format!(
                "planned_keywords={} planned_interval_seconds={} source_prompt_present={}",
                planned_keywords, planned_interval_seconds, planned_source_prompt_present
            ),
        ),
        LocalCheck::new(
            "workflow_artifact_evidence_present",
            registry_path_satisfied
                && registry_count == 1
                && !workflow_id.is_empty()
                && artifact_path_satisfied
                && spec_version == "workflow.v1"
                && spec_version_satisfied
                && source_url == EXPECTED_SOURCE_URL
                && source_url_satisfied
                && source_type == "hacker_news_front_page"
                && source_type_satisfied
                && extractor_type == "hacker_news_front_page_titles"
                && extractor_type_satisfied
                && extractor_selector == "span.titleline > a"
                && extractor_selector_satisfied
                && predicate_type == "contains_any_title"
                && predicate_type_satisfied
                && keywords_normalized == EXPECTED_KEYWORDS_NORMALIZED
                && keywords_satisfied
                && poll_interval_seconds == EXPECTED_POLL_INTERVAL_SECONDS
                && poll_interval_satisfied
                && sink_type == "assistant_notification"
                && sink_rail == "assistant"
                && sink_notification_class == "digest"
                && sink_type_satisfied
                && sink_rail_satisfied
                && sink_notification_class_satisfied
                && allowlist_satisfied
                && graph_shape_satisfied
                && next_run_at_ms > 0
                && next_run_satisfied
                && source_prompt_satisfied,
            truncate_chars(
                &format!(
                    "workflow_id={} source_url={} keywords={} poll_interval={} sink_type={} next_run_at_ms={}",
                    workflow_id,
                    source_url,
                    keywords_normalized,
                    poll_interval_seconds,
                    sink_type,
                    next_run_at_ms
                ),
                220,
            ),
        ),
        LocalCheck::new(
            "workflow_state_and_install_receipt_present",
            workflow_status.eq_ignore_ascii_case("active")
                && workflow_status_satisfied
                && state_path_satisfied
                && state_satisfied
                && state_seen_key_count == 0
                && state_last_run_ms == 0
                && state_last_success_ms == 0
                && state_failure_count == 0
                && install_receipt_path_satisfied
                && install_receipt_satisfied
                && install_authoring_tool == "automation.create_monitor"
                && install_trigger_kind == "interval"
                && install_valid.eq_ignore_ascii_case("true"),
            format!(
                "workflow_status={} state_seen_key_count={} last_run={} last_success={} failure_count={} install_authoring_tool={} install_trigger_kind={} install_valid={}",
                workflow_status,
                state_seen_key_count,
                state_last_run_ms,
                state_last_success_ms,
                state_failure_count,
                install_authoring_tool,
                install_trigger_kind,
                install_valid
            ),
        ),
        LocalCheck::new(
            "cec_receipts_present",
            cec_discovery_seen
                && cec_provider_selection_seen
                && cec_execution_seen
                && cec_verification_seen
                && has_cec_receipt(obs, "execution", "execution_artifact", Some(true))
                && has_cec_receipt(
                    obs,
                    "provider_selection",
                    "provider_selection_commit",
                    Some(true),
                )
                && cec_contract_gate_seen,
            truncate_chars(&format!("cec_receipts={:?}", obs.cec_receipts), 220),
        ),
        LocalCheck::new(
            "fixture_and_cleanup_evidence_present",
            fixture_mode == EXPECTED_FIXTURE_MODE
                && fixture_satisfied
                && run_unique_satisfied
                && automation_root_seeded_satisfied
                && manifest_seeded_satisfied
                && registry_absent_satisfied
                && receipts_absent_satisfied
                && cleanup_satisfied,
            format!(
                "fixture_mode={} run_unique={} automation_root_seeded={} manifest_seeded={} registry_absent={} receipts_absent={} cleanup={}",
                fixture_mode,
                run_unique_satisfied,
                automation_root_seeded_satisfied,
                manifest_seeded_satisfied,
                registry_absent_satisfied,
                receipts_absent_satisfied,
                cleanup_satisfied
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !has_contract_failure_evidence(obs) && hard_action_failure_count == 0,
            format!(
                "terminal_failure_reason={:?} action_error_classes={:?}",
                obs.terminal_failure_reason, obs.action_error_classes
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
