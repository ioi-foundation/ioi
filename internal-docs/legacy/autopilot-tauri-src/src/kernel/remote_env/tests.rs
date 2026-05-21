use super::{binding_scope_label, binding_value_preview, overlapping_binding_count};
use crate::models::SessionRemoteEnvBinding;

#[test]
fn binding_scope_classifies_routing_and_shell_keys() {
    assert_eq!(
        binding_scope_label("AUTOPILOT_CHAT_ARTIFACT_ROUTING_RUNTIME_URL"),
        "Routing runtime"
    );
    assert_eq!(binding_scope_label("XDG_SESSION_TYPE"), "Shell process");
    assert_eq!(binding_scope_label("OPENAI_API_KEY"), "Provider auth");
}

#[test]
fn binding_preview_redacts_secret_values() {
    assert_eq!(binding_value_preview("abc123", true), "Present (redacted)");
    assert_eq!(binding_value_preview("", true), "Not set");
    assert_eq!(
        binding_value_preview("http://127.0.0.1:11434/v1", false),
        "http://127.0.0.1:11434/v1"
    );
}

#[test]
fn overlapping_binding_count_detects_control_plane_and_process_drift() {
    let rows = vec![
        SessionRemoteEnvBinding {
            key: "OPENAI_API_KEY".to_string(),
            value_preview: "Present (redacted)".to_string(),
            source_label: "Local engine control plane".to_string(),
            scope_label: "Provider auth".to_string(),
            provenance_label: "Configured secret binding".to_string(),
            secret: true,
            redacted: true,
        },
        SessionRemoteEnvBinding {
            key: "OPENAI_API_KEY".to_string(),
            value_preview: "Present (redacted)".to_string(),
            source_label: "Runtime process".to_string(),
            scope_label: "Provider auth".to_string(),
            provenance_label: "Process secret".to_string(),
            secret: true,
            redacted: true,
        },
        SessionRemoteEnvBinding {
            key: "TZ".to_string(),
            value_preview: "UTC".to_string(),
            source_label: "Runtime process".to_string(),
            scope_label: "Shell process".to_string(),
            provenance_label: "Shell/runtime environment".to_string(),
            secret: false,
            redacted: false,
        },
    ];

    assert_eq!(overlapping_binding_count(&rows), 1);
}
