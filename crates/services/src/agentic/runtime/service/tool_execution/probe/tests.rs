use super::{
    is_command_probe_intent, is_system_clock_read_intent, summarize_command_probe_output,
    summarize_math_eval_output, summarize_structured_command_receipt_output,
    summarize_system_clock_or_plain_output, summarize_system_clock_output,
};
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};

#[test]
fn detects_command_probe_intent() {
    let resolved = ResolvedIntentState {
        intent_id: "command.probe".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.9,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v2".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_command_probe_intent(Some(&resolved)));
    let mut other = resolved.clone();
    other.intent_id = "command.exec".to_string();
    assert!(!is_command_probe_intent(Some(&other)));
    assert!(!is_command_probe_intent(None));
}

#[test]
fn detects_system_clock_read_intent() {
    let resolved = ResolvedIntentState {
        intent_id: "system.clock.read".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.9,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v2".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_system_clock_read_intent(Some(&resolved)));
}

#[test]
fn summarizes_system_clock_output() {
    let summary =
        summarize_system_clock_output("2026-02-23T01:23:45Z\n").expect("should produce summary");
    assert_eq!(summary, "2026-02-23T01:23:45Z");
}

#[test]
fn summarizes_system_clock_output_from_command_history_prefix() {
    let summary = summarize_system_clock_output(
        "COMMAND_HISTORY:{\"command\":\"date -u +%Y-%m-%dT%H:%M:%SZ\",\"exit_code\":0,\"stdout\":\"2026-02-23T13:36:27Z\",\"stderr\":\"\",\"timestamp_ms\":1771853787127,\"step_index\":0}\n2026-02-23T13:36:27Z\n",
    )
    .expect("should produce summary");
    assert_eq!(summary, "2026-02-23T13:36:27Z");
}

#[test]
fn summarizes_system_clock_output_from_embedded_command_history_timestamp() {
    let summary = summarize_system_clock_output(
        "Current UTC time: COMMAND_HISTORY:{\"stdout\":\"2026-02-23T13:36:27Z\"}",
    )
    .expect("should produce summary");
    assert_eq!(summary, "2026-02-23T13:36:27Z");
}

#[test]
fn does_not_summarize_non_timestamp_clock_output() {
    let summary = summarize_system_clock_output("9386\n");
    assert!(summary.is_none());
}

#[test]
fn falls_back_to_plain_output_when_clock_summary_not_available() {
    let summary = summarize_system_clock_or_plain_output("9386\n")
        .expect("should preserve plain non-timestamp output");
    assert_eq!(summary, "9386");
}

#[test]
fn summarizes_math_eval_output_with_numeric_result() {
    let summary =
        summarize_math_eval_output("Math result: 9,386\n").expect("math result should parse");
    assert_eq!(summary, "9,386");
}

#[test]
fn does_not_summarize_non_math_eval_output() {
    assert_eq!(
        summarize_math_eval_output("Created directory /tmp/demo"),
        None
    );
}

#[test]
fn summarizes_not_found_probe() {
    let tool = ioi_types::app::agentic::AgentTool::SysExec {
        command: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; else echo \"NOT_FOUND_IN_PATH\"; fi".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let summary =
        summarize_command_probe_output(&tool, "NOT_FOUND_IN_PATH").expect("should produce summary");
    assert!(summary.contains("gimp is not installed"));
}

#[test]
fn summarizes_not_found_probe_for_exec_session() {
    let tool = ioi_types::app::agentic::AgentTool::SysExecSession {
        command: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; else echo \"NOT_FOUND_IN_PATH\"; fi".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
    };
    let summary =
        summarize_command_probe_output(&tool, "NOT_FOUND_IN_PATH").expect("should produce summary");
    assert!(summary.contains("gimp is not installed"));
}

#[test]
fn summarizes_found_probe() {
    let tool = ioi_types::app::agentic::AgentTool::SysExec {
        command: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "if command -v gimp >/dev/null 2>&1; then echo \"FOUND: $(command -v gimp)\"; gimp --version; fi".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let output = "FOUND: /usr/bin/gimp\nGIMP 2.10.34";
    let summary = summarize_command_probe_output(&tool, output).expect("should produce summary");
    assert!(summary.contains("gimp is installed"));
    assert!(summary.contains("/usr/bin/gimp"));
    assert!(summary.contains("Version:"));
}

#[test]
fn summarizes_structured_shutdown_receipt_output() {
    let output = "provider=shutdown\ntarget_local_time=23:00\nscheduled=true\n";
    let summary = summarize_structured_command_receipt_output(output, Some(1_772_000_000_000))
        .expect("structured shutdown output should summarize");
    assert!(summary.contains("provider 'shutdown'"));
    assert!(summary.contains("23:00"));
}

#[test]
fn summarizes_structured_top_memory_receipt_output() {
    let output = "provider=ps\nrow|1|firefox-bin|6795|892632\nrow|2|soffice.bin|58757|795564\n";
    let summary = summarize_structured_command_receipt_output(output, None)
        .expect("structured top-memory output should summarize");
    assert!(summary.contains("Top memory apps"));
    assert!(summary.contains("firefox-bin"));
    assert!(summary.contains("pid 6795"));
    assert!(summary.contains("rss_kb 892632"));
}

#[test]
fn summarizes_structured_receipt_output_from_command_history_prefix() {
    let output = concat!(
        "COMMAND_HISTORY:{\"command\":\"/tmp/demo/top_memory_apps_probe 5\",\"exit_code\":0,",
        "\"stdout\":\"provider=ps\\nrow|1|firefox-bin|6795|892632\\n\",",
        "\"stderr\":\"\",\"timestamp_ms\":1772000000000,\"step_index\":2}\n"
    );
    let summary = summarize_structured_command_receipt_output(output, None)
        .expect("command history stdout should be summarized");
    assert!(summary.contains("Top memory apps"));
    assert!(summary.contains("firefox-bin"));
}

#[test]
fn summarizes_generic_command_receipt_output_from_command_history_prefix() {
    let output = concat!(
        "COMMAND_HISTORY:{\"command\":\"bash -lc echo clean-runtime-gui-check\",",
        "\"exit_code\":0,\"stdout\":\"clean-runtime-gui-check\\n\",",
        "\"stderr\":\"\",\"timestamp_ms\":1772000000000,\"step_index\":2}\n"
    );
    let summary = summarize_structured_command_receipt_output(output, None)
        .expect("generic command history stdout should be summarized");
    assert!(summary.contains("Command `bash -lc echo clean-runtime-gui-check` exited with code 0"));
    assert!(summary.contains("stdout:"));
    assert!(summary.contains("clean-runtime-gui-check"));
}

#[test]
fn summarizes_generic_command_receipt_output_when_stdout_is_empty() {
    let output = concat!(
        "COMMAND_HISTORY:{\"command\":\"bash -lc false\",",
        "\"exit_code\":1,\"stdout\":\"\",",
        "\"stderr\":\"\",\"timestamp_ms\":1772000000000,\"step_index\":2}\n"
    );
    let summary = summarize_structured_command_receipt_output(output, None)
        .expect("generic command history exit should be summarized");
    assert!(summary.contains("Command `bash -lc false` exited with code 1"));
}
