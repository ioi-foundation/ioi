use super::should_enable_local_gpu_profile_by_default;

#[test]
fn local_gpu_profile_auto_enables_for_detected_small_gpu_hosts() {
    assert!(should_enable_local_gpu_profile_by_default(
        false,
        None,
        None,
        None,
        Some("nvidia-vram-8gb-class"),
    ));
}

#[test]
fn local_gpu_profile_respects_non_local_explicit_profile() {
    assert!(!should_enable_local_gpu_profile_by_default(
        false,
        Some("desktop-default"),
        None,
        None,
        Some("nvidia-vram-8gb-class"),
    ));
}

#[test]
fn local_gpu_profile_respects_explicit_runtime_override() {
    assert!(!should_enable_local_gpu_profile_by_default(
        false,
        None,
        None,
        Some("http://127.0.0.1:9000/v1/chat/completions"),
        Some("nvidia-vram-8gb-class"),
    ));
}
