use super::*;

fn timeout_with_env(entries: &[(&str, &str)]) -> Duration {
    cognition_inference_timeout_from_env(|name| {
        entries
            .iter()
            .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
    })
}

#[test]
fn cognition_timeout_defaults_to_fifteen_seconds() {
    assert_eq!(timeout_with_env(&[]), Duration::from_secs(15));
}

#[test]
fn cognition_timeout_expands_in_local_gpu_dev_mode() {
    assert_eq!(
        timeout_with_env(&[("AUTOPILOT_LOCAL_GPU_DEV", "1")]),
        Duration::from_secs(60)
    );
}

#[test]
fn explicit_timeout_env_overrides_local_gpu_dev_default() {
    assert_eq!(
        timeout_with_env(&[
            ("AUTOPILOT_LOCAL_GPU_DEV", "1"),
            ("IOI_COGNITION_INFERENCE_TIMEOUT_SECS", "23"),
        ]),
        Duration::from_secs(23)
    );
}
