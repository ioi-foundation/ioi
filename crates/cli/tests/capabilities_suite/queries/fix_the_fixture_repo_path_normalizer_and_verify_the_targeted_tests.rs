use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    environment_bool, environment_value, has_cec_receipt, has_cec_stage, has_tool_with_token,
    has_typed_contract_failure_evidence, latest_parent_playbook_by_id,
    latest_parent_playbook_for_route, truncate_chars, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

const CASE_ID: &str = "fix_the_fixture_repo_path_normalizer_and_verify_the_targeted_tests";
const EXPECTED_FIXTURE_MODE: &str = "coding_path_normalizer_fixture_v1";
const EXPECTED_HIDDEN_PROBE_OUTPUT: &str = "./tmp/logs/latest.txt";
const EXPECTED_TARGETED_TEST_TOKEN: &str = "tests.test_path_utils";

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: concat!(
            "Port the path-normalization parity fix into the repo at ",
            "\"{CODING_PATH_NORMALIZER_REPO}\". ",
            "Work inside that repo root, patch only `path_utils.py`, and keep `tests/test_path_utils.py` unchanged. ",
            "Update `normalize_fixture_path` so it converts backslashes to forward slashes, collapses duplicate separators, ",
            "and preserves a leading `./` or `/`. ",
            "Run the focused verification command `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, ",
            "verify the final postcondition, and report the touched files plus command results."
        ),
        success_definition: "Use the explicit coding route to patch the isolated fixture repo, retain a passed targeted-test verifier scorecard, satisfy hidden path-normalization checks without mutating tests, and finish with cleanup receipts.",
        seeded_intent_id: "workspace.ops",
        intent_scope: IntentScopeProfile::WorkspaceOps,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 150,
        max_steps: 28,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let fixture_mode = environment_value(obs, "env_receipt::coding_path_normalizer_fixture_mode")
        .unwrap_or_default();
    let fixture_satisfied =
        environment_bool(obs, "env_receipt::coding_path_normalizer_fixture_satisfied")
            .unwrap_or(false);
    let targeted_tests_exit_code = environment_value(
        obs,
        "env_receipt::coding_path_normalizer_targeted_tests_exit_code",
    )
    .unwrap_or_default();
    let targeted_tests_satisfied = environment_bool(
        obs,
        "env_receipt::coding_path_normalizer_targeted_tests_exit_code_satisfied",
    )
    .unwrap_or(false);
    let hidden_probe_output = environment_value(
        obs,
        "env_receipt::coding_path_normalizer_hidden_probe_output",
    )
    .unwrap_or_default();
    let hidden_probe_satisfied = environment_bool(
        obs,
        "env_receipt::coding_path_normalizer_hidden_probe_output_satisfied",
    )
    .unwrap_or(false);
    let tests_unchanged = environment_bool(
        obs,
        "env_receipt::coding_path_normalizer_tests_unchanged_satisfied",
    )
    .unwrap_or(false);
    let source_mentions_function = environment_bool(
        obs,
        "env_receipt::coding_path_normalizer_source_mentions_function_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        environment_bool(obs, "env_receipt::coding_path_normalizer_scope_satisfied")
            .unwrap_or(false);
    let cleanup_satisfied =
        environment_bool(obs, "env_receipt::coding_path_normalizer_cleanup_satisfied")
            .unwrap_or(false);

    let coding_route = latest_parent_playbook_by_id(obs, "evidence_audited_patch")
        .or_else(|| latest_parent_playbook_for_route(obs, "coding"));
    let route_selected = coding_route
        .map(|receipt| {
            receipt.route_family.eq_ignore_ascii_case("coding")
                && receipt
                    .topology
                    .eq_ignore_ascii_case("planner_specialist_verifier")
                && receipt.verifier_state.eq_ignore_ascii_case("passed")
        })
        .unwrap_or(false);
    let coding_scorecard = coding_route.and_then(|receipt| receipt.coding_scorecard.as_ref());
    let verifier_passed = coding_scorecard
        .map(|scorecard| {
            scorecard.verdict.eq_ignore_ascii_case("passed")
                && scorecard.targeted_command_count > 0
                && scorecard.targeted_pass_count == scorecard.targeted_command_count
        })
        .unwrap_or(false);
    let patch_synthesis_ready = coding_route
        .and_then(|receipt| receipt.patch_synthesis.as_ref())
        .map(|summary| summary.verification_ready)
        .unwrap_or(false);

    let targeted_command_recorded = obs.command_history_evidence.iter().any(|entry| {
        entry.command.contains(EXPECTED_TARGETED_TEST_TOKEN)
            || entry.stdout.contains(EXPECTED_TARGETED_TEST_TOKEN)
            || entry.stderr.contains(EXPECTED_TARGETED_TEST_TOKEN)
    });
    let executor_tools_present = has_tool_with_token(&obs.workload_tools, "sys__exec_session")
        || has_tool_with_token(&obs.action_tools, "sys__exec_session")
        || !obs.command_history_evidence.is_empty();
    let cec_phase_receipts_present = has_cec_stage(obs, "execution", Some(true))
        && has_cec_stage(obs, "verification", Some(true))
        && has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let completion_evidence_present = obs.completed && !obs.failed && scope_satisfied;
    let contract_failures_absent = !has_typed_contract_failure_evidence(obs);

    LocalJudgeResult::from_checks(vec![
        LocalCheck::new(
            "coding_fixture_receipts_present",
            fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE)
                && fixture_satisfied
                && cleanup_satisfied,
            format!(
                "fixture_mode={} fixture_satisfied={} cleanup_satisfied={}",
                fixture_mode, fixture_satisfied, cleanup_satisfied
            ),
        ),
        LocalCheck::new(
            "coding_postconditions_hold",
            targeted_tests_satisfied
                && hidden_probe_satisfied
                && hidden_probe_output == EXPECTED_HIDDEN_PROBE_OUTPUT
                && tests_unchanged
                && source_mentions_function
                && scope_satisfied,
            format!(
                "targeted_exit={} targeted_ok={} hidden_probe={} hidden_ok={} tests_unchanged={} source_mentions_function={} scope_satisfied={}",
                targeted_tests_exit_code,
                targeted_tests_satisfied,
                hidden_probe_output,
                hidden_probe_satisfied,
                tests_unchanged,
                source_mentions_function,
                scope_satisfied
            ),
        ),
        LocalCheck::new(
            "coding_route_selected",
            route_selected,
            coding_route
                .map(|receipt| {
                    format!(
                        "playbook={} route_family={} topology={} verifier_state={} summary={}",
                        receipt.playbook_id,
                        receipt.route_family,
                        receipt.topology,
                        receipt.verifier_state,
                        truncate_chars(&receipt.summary, 140)
                    )
                })
                .unwrap_or_else(|| "missing evidence_audited_patch receipt".to_string()),
        ),
        LocalCheck::new(
            "coding_verifier_scorecard_passed",
            verifier_passed,
            coding_scorecard
                .map(|scorecard| {
                    format!(
                        "verdict={} targeted_passed={}/{} widening={} regressions={} notes={}",
                        scorecard.verdict,
                        scorecard.targeted_pass_count,
                        scorecard.targeted_command_count,
                        scorecard.widening_status,
                        scorecard.regression_status,
                        scorecard.notes.as_deref().unwrap_or("none")
                    )
                })
                .unwrap_or_else(|| "missing coding scorecard".to_string()),
        ),
        LocalCheck::new(
            "coding_patch_synthesis_ready",
            patch_synthesis_ready,
            coding_route
                .and_then(|receipt| receipt.patch_synthesis.as_ref())
                .map(|summary| {
                    format!(
                        "status={} touched_files={} verification_ready={}",
                        summary.status, summary.touched_file_count, summary.verification_ready
                    )
                })
                .unwrap_or_else(|| "missing patch synthesis summary".to_string()),
        ),
        LocalCheck::new(
            "coding_targeted_command_recorded",
            targeted_command_recorded && executor_tools_present,
            format!(
                "targeted_command_recorded={} executor_tools_present={} commands={}",
                targeted_command_recorded,
                executor_tools_present,
                truncate_chars(
                    &obs.command_history_evidence
                        .iter()
                        .map(|entry| entry.command.clone())
                        .collect::<Vec<_>>()
                        .join(" || "),
                    220
                )
            ),
        ),
        LocalCheck::new(
            "coding_cec_and_completion_present",
            cec_phase_receipts_present && completion_evidence_present,
            format!(
                "cec_phase_receipts_present={} completed={} failed={} final_status={}",
                cec_phase_receipts_present, obs.completed, obs.failed, obs.final_status
            ),
        ),
        LocalCheck::new(
            "coding_contract_failures_absent",
            contract_failures_absent,
            format!(
                "contract_failure={} action_error_classes={:?} routing_failure_classes={:?}",
                !contract_failures_absent, obs.action_error_classes, obs.routing_failure_classes
            ),
        ),
    ])
}
