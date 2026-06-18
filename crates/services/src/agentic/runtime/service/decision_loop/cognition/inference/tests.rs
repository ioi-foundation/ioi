use super::*;

fn timeout_with_env(entries: &[(&str, &str)]) -> Duration {
    cognition_inference_timeout_from_env(|name| {
        entries
            .iter()
            .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
    })
}

#[test]
fn cognition_timeout_defaults_to_thirty_seconds() {
    assert_eq!(timeout_with_env(&[]), Duration::from_secs(30));
}

#[test]
fn cognition_timeout_expands_in_local_gpu_dev_mode() {
    assert_eq!(
        timeout_with_env(&[("HYPERVISOR_LOCAL_GPU_DEV", "1")]),
        Duration::from_secs(90)
    );
}

#[test]
fn explicit_timeout_env_overrides_local_gpu_dev_default() {
    assert_eq!(
        timeout_with_env(&[
            ("HYPERVISOR_LOCAL_GPU_DEV", "1"),
            ("IOI_COGNITION_INFERENCE_TIMEOUT_SECS", "23"),
        ]),
        Duration::from_secs(23)
    );
}

#[test]
fn reply_only_cognition_gets_generation_budget_floor() {
    assert_eq!(
        cognition_inference_timeout_for_reply_mode_from_base(Duration::from_secs(30), true),
        Duration::from_secs(60)
    );
    assert_eq!(
        cognition_inference_timeout_for_reply_mode_from_base(Duration::from_secs(90), true),
        Duration::from_secs(90)
    );
    assert_eq!(
        cognition_inference_timeout_for_reply_mode_from_base(Duration::from_secs(30), false),
        Duration::from_secs(30)
    );
}

#[test]
fn no_content_stream_errors_are_retryable_runtime_conditions() {
    assert!(inference_error_is_retryable_no_content(
        "Host function error: OpenAI streaming response ended without content",
    ));
    assert!(inference_error_is_retryable_no_content(
        "Local Ollama native chat ended without content",
    ));

    let reason = inference_error_system_fail_reason(
        "Host function error: OpenAI streaming response ended without content",
    );
    assert!(reason.contains("ERROR_CLASS=RuntimeRetryable"));
    assert!(!reason.contains("UserInterventionNeeded"));
}
